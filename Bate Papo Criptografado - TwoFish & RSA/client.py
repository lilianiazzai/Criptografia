import socket
import threading
import json
from crypto_hibrido import RSA_Twofish

chaves_publicas_dos_pares = {}
minhas_chaves = RSA_Twofish()
meu_nome = None

def enviar_mensagens(s):
    while True:
        destinatario = input("Para quem você quer enviar a mensagem? (ou 'todos'): ").strip()
        mensagem_texto = input("Sua mensagem: ")

        if destinatario.lower() == "todos":
            # Envia mensagem em grupo
            try:
                for nome_dest in chaves_publicas_dos_pares.keys():
                    if nome_dest == meu_nome:
                        continue

                    chave_publica_str = chaves_publicas_dos_pares[nome_dest]
                    chave_publica_dest = minhas_chaves.import_public_key(chave_publica_str.encode('utf-8'))

                    chave_twofish = minhas_chaves.generate_twofish_key()
                    chave_criptografada = minhas_chaves.encrypt_key_with_rsa(chave_twofish, chave_publica_dest)

                    twofish_obj = minhas_chaves.get_twofish(chave_twofish)
                    mensagem_criptografada = twofish_obj.encrypt(mensagem_texto.encode('utf-8'))

                    pacote = {
                        'tipo': 'mensagem',
                        'remetente': meu_nome,
                        'destinatario': nome_dest,
                        'chave_criptografada_hex': chave_criptografada.hex(),
                        'mensagem_criptografada_hex': mensagem_criptografada.hex()
                    }

                    s.sendall((json.dumps(pacote) + "\n").encode('utf-8'))

                print("Mensagem enviada para todos.")
            except Exception as e:
                print(f"Erro ao enviar mensagem em grupo: {e}")
            continue

        # Envio individual (como antes)
        if destinatario not in chaves_publicas_dos_pares:
            print("Destinatário não encontrado ou lista de chaves não atualizada.")
            continue

        try:
            chave_publica_do_destinatario_str = chaves_publicas_dos_pares[destinatario]
            chave_publica_do_destinatario = minhas_chaves.import_public_key(chave_publica_do_destinatario_str.encode('utf-8'))
            
            chave_twofish_nova = minhas_chaves.generate_twofish_key()
            chave_criptografada = minhas_chaves.encrypt_key_with_rsa(chave_twofish_nova, chave_publica_do_destinatario)
            
            twofish_obj = minhas_chaves.get_twofish(chave_twofish_nova)
            mensagem_criptografada = twofish_obj.encrypt(mensagem_texto.encode('utf-8'))
            print(f"### [DEBUG] Mensagem cifrada (hex) para {destinatario}: {mensagem_criptografada.hex()} \n")

            pacote_mensagem = {
                'tipo': 'mensagem',
                'remetente': meu_nome,
                'destinatario': destinatario,
                'chave_criptografada_hex': chave_criptografada.hex(),
                'mensagem_criptografada_hex': mensagem_criptografada.hex()
            }

            s.sendall((json.dumps(pacote_mensagem) + "\n").encode('utf-8'))

        except Exception as e:
            print(f"Erro ao enviar mensagem: {e}")

def receber_mensagens(s):
    global chaves_publicas_dos_pares
    buffer = ""
    try:
        while True:
            parte = s.recv(4096)
            if not parte:
                print("Desconectado do servidor.")
                break
            buffer += parte.decode('utf-8')
            # processa todas as mensagens terminadas em '\n'
            while "\n" in buffer:
                linha, buffer = buffer.split("\n", 1)
                if not linha.strip():
                    continue
                try:
                    mensagem = json.loads(linha)
                except Exception as e:
                    print(f"Erro ao decodificar JSON recebido: {e}")
                    continue

                tipo_mensagem = mensagem.get('tipo')
                if tipo_mensagem == 'lista_chaves':
                    chaves_publicas_dos_pares = mensagem['chaves']
                    print("\n📜 Lista de chaves públicas atualizada:")
                    for nome in chaves_publicas_dos_pares.keys():
                        print(f" - {nome}")
                else:
                    # mensagem criptografada de outro cliente
                    remetente = mensagem.get('remetente')
                    encrypted_key = bytes.fromhex(mensagem['chave_criptografada_hex'])
                    encrypted_msg = bytes.fromhex(mensagem['mensagem_criptografada_hex'])

                    # Descriptografar a chave Twofish com a minha chave privada RSA
                    chave_twofish_descriptografada = minhas_chaves.decrypt_key_with_rsa(encrypted_key)
                    print(f"### [DEBUG] Chave Twofish recebida de {remetente}: {chave_twofish_descriptografada.hex()} \n")
                    twofish_do_remetente = minhas_chaves.get_twofish(chave_twofish_descriptografada)
                    print(f"### [DEBUG] Mensagem cifrada recebida de {remetente}: {encrypted_msg.hex()} \n")
                    mensagem_descriptografada = twofish_do_remetente.decrypt(encrypted_msg)
                    print(f"\n{remetente}: {mensagem_descriptografada.decode('utf-8')}")
    except Exception as e:
        print(f"Erro no recebimento: {e}")
    finally:
        s.close()

def iniciar_cliente():
    global meu_nome, minhas_chaves
    meu_nome = input("Digite seu nome de usuário: ")

    print("Gerando seu par de chaves RSA...")
    minhas_chaves = RSA_Twofish()

    cliente_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente_socket.connect(('127.0.0.1', 9999))
    except ConnectionRefusedError:
        print("Erro: Não foi possível conectar ao servidor. Verifique se o servidor está rodando.")
        return

    # Enviar dados iniciais terminados com '\n' (framing)
    dados_iniciais = {
        'nome': meu_nome,
        'chave_publica': minhas_chaves.export_public_key().decode('utf-8')
    }
    cliente_socket.sendall((json.dumps(dados_iniciais) + "\n").encode('utf-8'))

    threading.Thread(target=receber_mensagens, args=(cliente_socket,), daemon=True).start()
    threading.Thread(target=enviar_mensagens, args=(cliente_socket,), daemon=True).start()

    # manter o programa vivo
    try:
        while True:
            pass
    except KeyboardInterrupt:
        print("Saindo...")
        cliente_socket.close()

if __name__ == "__main__":
    iniciar_cliente()