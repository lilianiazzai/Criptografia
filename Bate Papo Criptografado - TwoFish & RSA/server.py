import socket
import threading
import json
import traceback

# Dicionário para armazenar as chaves públicas dos clientes
# formato: {nome: {'conexao': socket, 'endereco': addr, 'chave_publica': str_b64}}
clientes = {}
lock = threading.Lock()

def enviar_json_com_delimitador(con, obj):
    """Envia um objeto JSON seguido de '\\n' como delimitador."""
    try:
        data = (json.dumps(obj) + "\n").encode("utf-8")
        con.sendall(data)
    except Exception as e:
        # Não crashar o servidor; log e deixar o chamador lidar com remoção se necessário.
        print(f"[send error] {e}")
        raise

def montar_lista_chaves_exceto(nome_excluir):
    """Retorna dict de chaves públicas de todos exceto nome_excluir."""
    with lock:
        return {
            nome: dados['chave_publica']
            for nome, dados in clientes.items()
            if nome != nome_excluir
        }

def broadcast_lista_chaves():
    """Envia a lista de chaves atualizada para TODOS os clientes."""
    with lock:
        # constroi mapa único para evitar inconsistências
        mapa_chaves = {nome: dados['chave_publica'] for nome, dados in clientes.items()}
        payload = {'tipo': 'lista_chaves', 'chaves': mapa_chaves}
        remocao = []
        for nome, dados in list(clientes.items()):
            con = dados['conexao']
            try:
                enviar_json_com_delimitador(con, payload)
            except Exception as e:
                print(f"Erro ao atualizar lista de chaves para {nome}: {e}")
                remocao.append(nome)
        # remover conexões problemáticas
        for nome in remocao:
            try:
                clientes[nome]['conexao'].close()
            except:
                pass
            del clientes[nome]

def gerenciar_cliente(conexao, endereco):
    nome_usuario = None
    try:
        # Receber dados iniciais (esperamos um JSON completo terminado por '\n')
        buffer = ""
        # receber até o primeiro '\n'
        while True:
            parte = conexao.recv(4096).decode('utf-8')
            if not parte:
                raise ConnectionError("Conexão fechada durante a inicialização")
            buffer += parte
            if "\n" in buffer:
                linha, resto = buffer.split("\n", 1)
                buffer = resto  # caso haja dados extras (possível)
                dados_iniciais = json.loads(linha)
                break

        nome_usuario = dados_iniciais['nome']
        chave_publica = dados_iniciais['chave_publica']

        with lock:
            clientes[nome_usuario] = {
                'conexao': conexao,
                'endereco': endereco,
                'chave_publica': chave_publica
            }

        print(f"Cliente '{nome_usuario}' conectado de {endereco}.")

        # 1) Enviar ao novo cliente a lista atual (todos exceto ele)
        chaves_para_novo = montar_lista_chaves_exceto(nome_usuario)
        enviar_json_com_delimitador(conexao, {'tipo': 'lista_chaves', 'chaves': chaves_para_novo})

        # 2) Informar todos os outros (broadcast) sobre a lista atualizada
        broadcast_lista_chaves()

        # Agora ficar processando mensagens do cliente (usa buffer para lidar com framing)
        recv_buffer = buffer  # iniciar com o que sobrou (pode ser vazio)
        while True:
            if "\n" not in recv_buffer:
                parte = conexao.recv(4096)
                if not parte:
                    # Conexão fechada pelo cliente
                    break
                recv_buffer += parte.decode('utf-8')
            # processa todas as linhas completas
            while "\n" in recv_buffer:
                linha, recv_buffer = recv_buffer.split("\n", 1)
                if not linha.strip():
                    continue
                try:
                    mensagem = json.loads(linha)
                except Exception as e:
                    print(f"JSON inválido recebido de {nome_usuario}: {e}")
                    continue

                # encaminhar mensagens
                encaminhar_mensagem(mensagem)

    except Exception as e:
        print(f"Erro em gerenciar_cliente ({endereco}): {e}")
        traceback.print_exc()
    finally:
        # cleanup
        if nome_usuario:
            print(f"Cliente '{nome_usuario}' desconectado.")
            with lock:
                if nome_usuario in clientes:
                    try:
                        clientes[nome_usuario]['conexao'].close()
                    except:
                        pass
                    del clientes[nome_usuario]
            # avisar os demais sobre a remoção
            broadcast_lista_chaves()
        else:
            try:
                conexao.close()
            except:
                pass

def encaminhar_mensagem(mensagem):
    destinatario = mensagem.get('destinatario')
    remetente = mensagem.get('remetente')
    
    if not destinatario or not remetente:
        print("Mensagem com formato inválido (sem remetente/destinatario).")
        return

    with lock:
        if destinatario == "todos":
            print(f"Broadcast de '{mensagem['remetente']}' para todos os clientes.")
            with lock:
                for nome, dados in clientes.items():
                    if nome != mensagem['remetente']:
                        try:
                            dados['conexao'].sendall((json.dumps(mensagem) + "\n").encode('utf-8'))
                        except Exception as e:
                            print(f"Erro ao enviar broadcast para {nome}: {e}")
            return

        if destinatario in clientes:
            try:
                con_dest = clientes[destinatario]['conexao']
                # enviar JSON com delimitador
                enviar_json_com_delimitador(con_dest, mensagem)
                print(f"Encaminhada de '{remetente}' para '{destinatario}'.")
            except Exception as e:
                print(f"Erro ao encaminhar para {destinatario}: {e}")
        else:
            print(f"Destinatário '{destinatario}' não encontrado. Mensagem descartada.")

def iniciar_servidor(host='0.0.0.0', port=9999):
    servidor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor_socket.bind((host, port))
    servidor_socket.listen(10)
    print(f"Servidor de bate-papo iniciado em {host}:{port}...")

    try:
        while True:
            conexao, endereco = servidor_socket.accept()
            thread = threading.Thread(target=gerenciar_cliente, args=(conexao, endereco), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("Servidor encerrando...")
    finally:
        servidor_socket.close()

if __name__ == "__main__":
    iniciar_servidor()
