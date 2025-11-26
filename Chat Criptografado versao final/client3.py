import socket
import threading
import json
import binascii
import sys
import time
from crypto_hibrido3 import RSA_Twofish  # Importando da versão atualizada

# Estado global do cliente
chaves_publicas_dos_pares = {}
minhas_chaves = None
meu_nome = None

# Limites e parâmetros
MAX_MESSAGE_SIZE = 10000
RECONNECT_DELAY = 2  # segundos antes de tentar reconectar


def log(pilar, mensagem):
    print(f"[{pilar}] {mensagem}")


def enviar_mensagens(s):
    """Thread responsável por ler o input do usuário e enviar mensagens cifradas."""
    while True:
        try:
            destinatario = input("\nPara quem? (ou 'todos'): ").strip()
            if not destinatario:
                continue

            mensagem_texto = input("Mensagem: ").strip()
            if not mensagem_texto:
                continue

            if len(mensagem_texto) > MAX_MESSAGE_SIZE:
                log('DISPONIBILIDADE', 'Mensagem muito grande. Reduza o tamanho.')
                continue

            # === 1. ASSINATURA (Não Repúdio) ===
            assinatura_b64 = minhas_chaves.sign_message(mensagem_texto.encode('utf-8'))
            log('NAO-REPUDIO', f'Mensagem assinada por {meu_nome}. Assinatura (base64, início): {assinatura_b64[:30]}...')

            # Determina lista de destinatários
            if destinatario.lower() == 'todos':
                destinos = [nome for nome in chaves_publicas_dos_pares.keys() if nome != meu_nome]
                if not destinos:
                    log('DISPONIBILIDADE', 'Nenhum outro usuário disponível para broadcast.')
                    continue
                log('AUTENTICIDADE', f'Iniciando envio em grupo para: {destinos}')
            else:
                if destinatario not in chaves_publicas_dos_pares:
                    log('AUTENTICIDADE', f"Usuário '{destinatario}' não encontrado na lista de chaves.")
                    continue
                destinos = [destinatario]

            # Envia a mensagem individualmente para cada destinatário (Envelope RSA por destinatário)
            for nome_dest in destinos:
                try:
                    pub_key_str = chaves_publicas_dos_pares[nome_dest]
                    pub_key_dest = minhas_chaves.import_public_key(pub_key_str)

                    # B. Gerar chave de sessão (Twofish)
                    chave_twofish = minhas_chaves.generate_twofish_key()
                    log('CONFIDENCIALIDADE', f'Chave Twofish gerada (hex inicio): {binascii.hexlify(chave_twofish).decode()[:16]}...')

                    # C. Cifrar a chave Twofish com RSA (Envelope)
                    chave_cifrada_b64 = minhas_chaves.encrypt_key_with_rsa(chave_twofish, pub_key_dest)
                    log('CONFIDENCIALIDADE', f'Chave de sessão encapsulada para {nome_dest} (base64 inicio): {chave_cifrada_b64[:30]}...')

                    # D. Cifrar a mensagem com Twofish
                    twofish_obj = minhas_chaves.get_twofish(chave_twofish)
                    msg_cifrada_bytes = twofish_obj.encrypt(mensagem_texto.encode('utf-8'))
                    msg_cifrada_hex = binascii.hexlify(msg_cifrada_bytes).decode('utf-8')
                    log('CONFIDENCIALIDADE', f'Mensagem cifrada destinada a {nome_dest} (hex inicio): {msg_cifrada_hex[:32]}...')

                    pacote = {
                        'tipo': 'mensagem',
                        'remetente': meu_nome,
                        'destinatario': nome_dest,
                        'conteudo': msg_cifrada_hex,
                        'chave_sessao': chave_cifrada_b64,
                        'assinatura': assinatura_b64
                    }

                    s.sendall((json.dumps(pacote) + "\n").encode('utf-8'))
                    log('DISPONIBILIDADE', f'Mensagem segura enviada para {nome_dest}.')

                except Exception as e:
                    log('DISPONIBILIDADE', f'Falha ao enviar para {nome_dest}: {e}')

        except KeyboardInterrupt:
            log('DISPONIBILIDADE', 'Encerrando cliente por KeyboardInterrupt')
            try:
                s.close()
            except:
                pass
            sys.exit()
        except Exception as e:
            log('DISPONIBILIDADE', f'Erro no loop de envio: {e}')


def processar_pacote_de_mensagem(pacote):
    remetente = pacote['remetente']
    msg_cifrada_hex = pacote['conteudo']
    chave_cifrada_b64 = pacote['chave_sessao']
    assinatura_b64 = pacote['assinatura']

    log('CONFIDENCIALIDADE', f'Pacote cifrado recebido de {remetente} (hex inicio): {str(msg_cifrada_hex)[:32]}...')

    # 1. Decifrar a Chave Twofish
    try:
        chave_twofish = minhas_chaves.decrypt_key_with_rsa(chave_cifrada_b64)
        log('CONFIDENCIALIDADE', f'Chave de sessão decifrada (hex inicio): {binascii.hexlify(chave_twofish).decode()[:16]}...')
    except Exception as e:
        log('INTEGRIDADE', f'Falha ao decifrar chave de sessão: {e}')
        return

    # 2. Decifrar a Mensagem
    try:
        twofish_obj = minhas_chaves.get_twofish(chave_twofish)
        msg_bytes = binascii.unhexlify(msg_cifrada_hex)
        texto_plano_bytes = twofish_obj.decrypt(msg_bytes)
        log('INTEGRIDADE', 'Padding e decifragem validados.')
    except Exception as e:
        log('INTEGRIDADE', f'Falha na decifragem: {e}')
        return

    # 3. Verificar Assinatura
    if remetente in chaves_publicas_dos_pares:
        pub_key_remetente_str = chaves_publicas_dos_pares[remetente]
        pub_key_remetente = minhas_chaves.import_public_key(pub_key_remetente_str)

        is_autentico = minhas_chaves.verify_signature(
            texto_plano_bytes,
            assinatura_b64,
            pub_key_remetente
        )

        if is_autentico:
            log('AUTENTICIDADE', 'Assinatura válida. Remetente confirmado.')
            log('NAO-REPUDIO', f'Mensagem assinada por {remetente} confirmada. Hash da mensagem (SHA-256): {__hash_message_hex(texto_plano_bytes)}')
            print(f"\n💬 MENSAGEM DE {remetente}: {texto_plano_bytes.decode('utf-8')}")
        else:
            log('AUTENTICIDADE', 'Assinatura inválida! Possível falsificação.')
    else:
        log('AUTENTICIDADE', f'Chave pública de {remetente} desconhecida. Não foi possível verificar assinatura.')


def receber_mensagens(s):
    global chaves_publicas_dos_pares
    buffer = ""
    try:
        while True:
            parte = s.recv(4096)
            if not parte:
                log('DISPONIBILIDADE', 'Desconectado do servidor.')
                break

            buffer += parte.decode('utf-8')

            while "\n" in buffer:
                linha, buffer = buffer.split("\n", 1)
                if not linha.strip():
                    continue
                try:
                    pacote = json.loads(linha)
                except Exception as e:
                    log('INTEGRIDADE', f'JSON inválido recebido: {e}')
                    continue

                tipo = pacote.get('tipo')

                if tipo == 'lista_chaves':
                    chaves_publicas_dos_pares = pacote['chaves']
                    log('AUTENTICIDADE', f'Lista de chaves atualizada: {list(chaves_publicas_dos_pares.keys())}')

                elif tipo == 'mensagem':
                    processar_pacote_de_mensagem(pacote)

    except Exception as e:
        log('DISPONIBILIDADE', f'Erro no loop de recebimento: {e}')
    finally:
        try:
            s.close()
        except:
            pass


def __hash_message_hex(msg_bytes: bytes) -> str:
    import hashlib
    return hashlib.sha256(msg_bytes).hexdigest()


def iniciar_cliente(host='127.0.0.1', port=9999):
    global meu_nome, minhas_chaves

    print('--- SECURE CHAT CLIENT (REVISADO) ---')
    meu_nome = input('Digite seu nome de usuário: ').strip()

    minhas_chaves = RSA_Twofish(verbose=True)

    cliente_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente_socket.connect((host, port))
    except ConnectionRefusedError:
        log('DISPONIBILIDADE', 'Servidor offline. Tentando reconectar...')
        time.sleep(RECONNECT_DELAY)
        try:
            cliente_socket.connect((host, port))
        except Exception as e:
            log('DISPONIBILIDADE', f'Falha ao conectar: {e}')
            return

    # Handshake inicial
    dados_iniciais = {
        'nome': meu_nome,
        'chave_publica': minhas_chaves.export_public_key()
    }
    cliente_socket.sendall((json.dumps(dados_iniciais) + "\n").encode('utf-8'))

    # Threads
    t_recv = threading.Thread(target=receber_mensagens, args=(cliente_socket,), daemon=True)
    t_send = threading.Thread(target=enviar_mensagens, args=(cliente_socket,), daemon=True)

    t_recv.start()
    t_send.start()

    try:
        while t_recv.is_alive() and t_send.is_alive():
            time.sleep(0.1)
    except KeyboardInterrupt:
        log('DISPONIBILIDADE', 'Saindo...')
        cliente_socket.close()


if __name__ == '__main__':
    iniciar_cliente()