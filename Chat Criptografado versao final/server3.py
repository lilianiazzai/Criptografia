# Revised server2.py implementing enhanced 5-pillar security logging
# (Confidentiality, Integrity, Authenticity, Availability, Non-Repudiation)

import socket
import threading
import json
import traceback

clientes = {}
lock = threading.Lock()

MAX_MESSAGE_SIZE = 20000  # evita flood simples


def enviar_json_com_delimitador(con, obj):
    try:
        data = (json.dumps(obj) + "\n").encode("utf-8")
        con.sendall(data)
        print(f"[DISPONIBILIDADE] Pacote enviado ao cliente ({len(data)} bytes).")
    except Exception as e:
        print(f"[DISPONIBILIDADE] ERRO ao enviar pacote: {e}")
        raise


def montar_lista_chaves_exceto(nome_excluir):
    with lock:
        return {
            nome: dados['chave_publica']
            for nome, dados in clientes.items()
            if nome != nome_excluir
        }


def broadcast_lista_chaves():
    with lock:
        mapa = {nome: dados['chave_publica'] for nome, dados in clientes.items()}
        payload = {'tipo': 'lista_chaves', 'chaves': mapa}
        print(f"[INTEGRIDADE - PKI] Broadcast de chaves para {len(clientes)} usuários.")

        remover = []
        for nome, dados in list(clientes.items()):
            try:
                enviar_json_com_delimitador(dados['conexao'], payload)
            except:
                remover.append(nome)

        for nome in remover:
            try:
                clientes[nome]['conexao'].close()
            except:
                pass
            del clientes[nome]
            print(f"[DISPONIBILIDADE] Cliente removido por falha: {nome}")


def gerenciar_cliente(con, endereco):
    nome = None
    try:
        buffer = ""
        while True:
            parte = con.recv(4096).decode('utf-8')
            if not parte:
                raise ConnectionError("Cliente desconectou durante handshake")
            buffer += parte
            if "\n" in buffer:
                linha, buffer = buffer.split("\n", 1)
                iniciais = json.loads(linha)
                break

        nome = iniciais['nome']
        chave_pub = iniciais['chave_publica']

        with lock:
            clientes[nome] = {
                'conexao': con,
                'endereco': endereco,
                'chave_publica': chave_pub
            }

        print(f"\n[DISPONIBILIDADE] Cliente '{nome}' conectado em {endereco}.")
        print(f"[AUTENTICIDADE] Chave pública de '{nome}' registrada.")

        enviar_json_com_delimitador(con, {
            'tipo': 'lista_chaves',
            'chaves': montar_lista_chaves_exceto(nome)
        })

        broadcast_lista_chaves()

        recv_buffer = buffer
        while True:
            if "\n" not in recv_buffer:
                parte = con.recv(4096)
                if not parte:
                    break
                recv_buffer += parte.decode('utf-8')

            while "\n" in recv_buffer:
                linha, recv_buffer = recv_buffer.split("\n", 1)
                if not linha.strip():
                    continue

                if len(linha) > MAX_MESSAGE_SIZE:
                    print(f"[DISPONIBILIDADE] Pacote muito grande de {nome}. Bloqueado.")
                    continue

                try:
                    objeto = json.loads(linha)
                except:
                    print(f"[INTEGRIDADE] JSON malformado de {nome}.")
                    continue

                encaminhar_mensagem(objeto)

    except Exception as e:
        print(f"[LOG] Cliente '{nome}' caiu: {e}")

    finally:
        if nome:
            print(f"[DISPONIBILIDADE] Removendo '{nome}'...")
            with lock:
                if nome in clientes:
                    try:
                        clientes[nome]['conexao'].close()
                    except:
                        pass
                    del clientes[nome]
            broadcast_lista_chaves()
        try:
            con.close()
        except:
            pass


def encaminhar_mensagem(msg):
    dest = msg.get('destinatario')
    remet = msg.get('remetente')
    conteudo = msg.get('conteudo', '')

    print("\n--- [ROTEAMENTO] ---")
    print(f"Mensagem de {remet} para {dest}")
    print(f"[CONFIDENCIALIDADE] Conteúdo cifrado visto pelo servidor: {str(conteudo)[:50]}...")

    if dest == 'todos':
        print("[DISPONIBILIDADE] Broadcast solicitado.")
        with lock:
            for nome, dados in clientes.items():
                if nome != remet:
                    try:
                        enviar_json_com_delimitador(dados['conexao'], msg)
                    except:
                        print(f"[ERRO] Falha ao enviar broadcast para {nome}")
        return

    with lock:
        if dest not in clientes:
            print(f"[DISPONIBILIDADE] Destinatário '{dest}' não encontrado.")
            return
        try:
            enviar_json_com_delimitador(clientes[dest]['conexao'], msg)
            print("[DISPONIBILIDADE] Mensagem entregue ao destinatário.")
        except Exception as e:
            print(f"[DISPONIBILIDADE] Falha ao entregar a {dest}: {e}")


def iniciar_servidor(host='0.0.0.0', port=9999):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((host, port))
        sock.listen(10)

        print("\n=========================================================")
        print(f"[SERVIDOR ATIVO] Porta {port} escutando...")
        print("[DISPONIBILIDADE] Aguardando conexões...")
        print("=========================================================")

        while True:
            con, end = sock.accept()
            t = threading.Thread(target=gerenciar_cliente, args=(con, end), daemon=True)
            t.start()

    except KeyboardInterrupt:
        print("[SHUTDOWN] Encerrando servidor...")
    except Exception as e:
        print(f"[CRITICAL] Erro no servidor: {e}")
        traceback.print_exc()
    finally:
        sock.close()


if __name__ == "__main__":
    iniciar_servidor()
