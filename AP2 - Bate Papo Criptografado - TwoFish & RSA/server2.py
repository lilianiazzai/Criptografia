import socket
import threading
import json
import traceback

# Dicionário para armazenar as chaves públicas dos clientes
clientes = {}
lock = threading.Lock()

def enviar_json_com_delimitador(con, obj):
    """Envia um objeto JSON seguido de '\\n' como delimitador."""
    try:
        data = (json.dumps(obj) + "\n").encode("utf-8")
        con.sendall(data)
    except Exception as e:
        print(f"[ERRO DE REDE] Falha ao enviar dados: {e}")
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
        mapa_chaves = {nome: dados['chave_publica'] for nome, dados in clientes.items()}
        payload = {'tipo': 'lista_chaves', 'chaves': mapa_chaves}
        
        print(f"[INTEGRIDADE - PKI] Distribuindo chaves públicas atualizadas para {len(clientes)} usuários...")
        
        remocao = []
        for nome, dados in list(clientes.items()):
            con = dados['conexao']
            try:
                enviar_json_com_delimitador(con, payload)
            except Exception as e:
                print(f"[ERRO] Falha ao atualizar lista para {nome}: {e}")
                remocao.append(nome)
        
        # Clean up de conexões mortas
        for nome in remocao:
            try:
                clientes[nome]['conexao'].close()
            except:
                pass
            del clientes[nome]

def gerenciar_cliente(conexao, endereco):
    nome_usuario = None
    try:
        # Receber dados iniciais
        buffer = ""
        while True:
            parte = conexao.recv(4096).decode('utf-8')
            if not parte:
                raise ConnectionError("Conexão fechada durante handshake")
            buffer += parte
            if "\n" in buffer:
                linha, resto = buffer.split("\n", 1)
                buffer = resto
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

        print(f"\n[DISPONIBILIDADE] Novo cliente conectado: '{nome_usuario}' ({endereco})")
        print(f"[AUTENTICIDADE] Chave Pública de '{nome_usuario}' registrada com sucesso.")

        # 1) Enviar ao novo cliente a lista atual
        chaves_para_novo = montar_lista_chaves_exceto(nome_usuario)
        enviar_json_com_delimitador(conexao, {'tipo': 'lista_chaves', 'chaves': chaves_para_novo})

        # 2) Informar todos os outros
        broadcast_lista_chaves()

        # Loop de mensagens
        recv_buffer = buffer
        while True:
            if "\n" not in recv_buffer:
                parte = conexao.recv(4096)
                if not parte:
                    break
                recv_buffer += parte.decode('utf-8')
            
            while "\n" in recv_buffer:
                linha, recv_buffer = recv_buffer.split("\n", 1)
                if not linha.strip():
                    continue
                try:
                    mensagem = json.loads(linha)
                except Exception as e:
                    print(f"[ERRO] JSON malformado de {nome_usuario}: {e}")
                    continue

                # Encaminhar
                encaminhar_mensagem(mensagem)

    except Exception as e:
        print(f"[LOG] Conexão com '{nome_usuario}' encerrada: {e}")
    finally:
        if nome_usuario:
            print(f"[DISPONIBILIDADE] Cliente '{nome_usuario}' desconectado. Limpando registros...")
            with lock:
                if nome_usuario in clientes:
                    try:
                        clientes[nome_usuario]['conexao'].close()
                    except:
                        pass
                    del clientes[nome_usuario]
            broadcast_lista_chaves()
        else:
            try:
                conexao.close()
            except:
                pass

def encaminhar_mensagem(mensagem):
    destinatario = mensagem.get('destinatario')
    remetente = mensagem.get('remetente')
    # Pegamos o conteúdo apenas para mostrar no log que ele é ilegível
    conteudo_cifrado = mensagem.get('conteudo', '') 
    
    # Truque para printar só um pedaço se for muito grande
    preview_cifrado = str(conteudo_cifrado)[:50] + "..." if conteudo_cifrado else "N/A"

    if not destinatario or not remetente:
        return

    print(f"\n--- [ROTEAMENTO DE MENSAGEM] ---")
    print(f"   De: {remetente} -> Para: {destinatario}")
    # PROVA DE CONFIDENCIALIDADE: O servidor vê isso aqui ó:
    print(f"   [CONFIDENCIALIDADE] Payload (Visto pelo Servidor): {preview_cifrado}")

    with lock:
        # Lógica de Broadcast (Se o chat em grupo for implementado no cliente)
        if destinatario == "todos":
            print(f"   [BROADCAST] Enviando para todos os usuários conectados.")
            for nome, dados in clientes.items():
                if nome != remetente:
                    try:
                        dados['conexao'].sendall((json.dumps(mensagem) + "\n").encode('utf-8'))
                    except Exception as e:
                        print(f"   [ERRO] Falha ao enviar broadcast para {nome}")
            return

        # Lógica P2P via Server
        if destinatario in clientes:
            try:
                con_dest = clientes[destinatario]['conexao']
                enviar_json_com_delimitador(con_dest, mensagem)
                print(f"   [SUCESSO] Mensagem entregue ao socket de destino.")
            except Exception as e:
                print(f"   [ERRO] Falha na entrega para {destinatario}: {e}")
        else:
            print(f"   [ALERTA] Destinatário '{destinatario}' não encontrado/offline.")

def iniciar_servidor(host='0.0.0.0', port=9999):
    servidor_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        servidor_socket.bind((host, port))
        servidor_socket.listen(10)
        print("\n" + "="*50)
        print(f"[SERVIDOR ATIVO] Escutando na porta {port}")
        print(f"[DISPONIBILIDADE] Aguardando conexões seguras...")
        print("="*50 + "\n")

        while True:
            conexao, endereco = servidor_socket.accept()
            thread = threading.Thread(target=gerenciar_cliente, args=(conexao, endereco), daemon=True)
            thread.start()
    except KeyboardInterrupt:
        print("\n[SHUTDOWN] Servidor encerrando manualmente...")
    except Exception as e:
        print(f"[CRITICAL] Erro no servidor: {e}")
        traceback.print_exc()
    finally:
        servidor_socket.close()

if __name__ == "__main__":
    iniciar_servidor()