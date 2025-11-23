import socket
import threading
import json
import binascii
import sys
from crypto_hibrido2 import RSA_Twofish  # Importando da versão atualizada

# Estado global do cliente
chaves_publicas_dos_pares = {}
minhas_chaves = None
meu_nome = None

def enviar_mensagens(s):
    """Thread responsável por ler o input do usuário e enviar mensagens cifradas."""
    while True:
        try:
            # Input bloqueante (pode atrapalhar a visualização de logs, mas é o padrão simples)
            destinatario = input("\nPara quem? (ou 'todos'): ").strip()
            if not destinatario: continue
            
            mensagem_texto = input("Mensagem: ").strip()
            if not mensagem_texto: continue

            # === 1. ASSINATURA (Não Repúdio) ===
            # Assinamos o texto original ANTES de criptografar
            assinatura_b64 = minhas_chaves.sign_message(mensagem_texto.encode('utf-8'))

            # Lista de destinos (se for "todos", pega todo mundo, senão só o alvo)
            lista_destinos = []
            if destinatario.lower() == "todos":
                lista_destinos = [nome for nome in chaves_publicas_dos_pares.keys() if nome != meu_nome]
            elif destinatario in chaves_publicas_dos_pares:
                lista_destinos = [destinatario]
            else:
                print(f"[ERRO] Usuário '{destinatario}' não encontrado na lista de chaves.")
                continue

            # Envia para cada destinatário (Criptografia de Ponta a Ponta)
            for nome_dest in lista_destinos:
                try:
                    # A. Importar chave pública do destino
                    pub_key_str = chaves_publicas_dos_pares[nome_dest]
                    pub_key_dest = minhas_chaves.import_public_key(pub_key_str)

                    # B. Gerar chave de sessão (Twofish)
                    chave_twofish = minhas_chaves.generate_twofish_key()

                    # C. Cifrar a chave Twofish com RSA (Confidencialidade da Chave)
                    # O método encrypt_key_with_rsa já retorna string base64
                    chave_cifrada_b64 = minhas_chaves.encrypt_key_with_rsa(chave_twofish, pub_key_dest)

                    # D. Cifrar a mensagem com Twofish (Confidencialidade da Mensagem)
                    twofish_obj = minhas_chaves.get_twofish(chave_twofish)
                    msg_cifrada_bytes = twofish_obj.encrypt(mensagem_texto.encode('utf-8'))
                    msg_cifrada_hex = binascii.hexlify(msg_cifrada_bytes).decode('utf-8')

                    # Montar pacote
                    pacote = {
                        'tipo': 'mensagem',
                        'remetente': meu_nome,
                        'destinatario': nome_dest,
                        'conteudo': msg_cifrada_hex,       # Mensagem cifrada (Hex)
                        'chave_sessao': chave_cifrada_b64, # Chave cifrada (Base64)
                        'assinatura': assinatura_b64       # Assinatura (Base64)
                    }

                    # Enviar JSON
                    s.sendall((json.dumps(pacote) + "\n").encode('utf-8'))
                    print(f"[ENVIADO] Mensagem segura enviada para '{nome_dest}'.")

                except Exception as e:
                    print(f"[ERRO] Falha ao enviar para {nome_dest}: {e}")

        except KeyboardInterrupt:
            sys.exit()
        except Exception as e:
            print(f"[CRASH] Erro no loop de envio: {e}")

def receber_mensagens(s):
    """Thread responsável por receber dados da rede e decifrar."""
    global chaves_publicas_dos_pares
    buffer = ""
    try:
        while True:
            parte = s.recv(4096)
            if not parte:
                print("\n[REDE] Desconectado do servidor.")
                break
            
            buffer += parte.decode('utf-8')
            
            while "\n" in buffer:
                linha, buffer = buffer.split("\n", 1)
                if not linha.strip(): continue
                
                try:
                    pacote = json.loads(linha)
                except Exception as e:
                    print(f"[ERRO] JSON inválido: {e}")
                    continue

                tipo = pacote.get('tipo')

                # === CASO 1: ATUALIZAÇÃO DE CHAVES (PKI) ===
                if tipo == 'lista_chaves':
                    chaves_publicas_dos_pares = pacote['chaves']
                    print(f"\n[SISTEMA] Lista de usuários atualizada: {list(chaves_publicas_dos_pares.keys())}")
                
                # === CASO 2: MENSAGEM DE CHAT ===
                elif tipo == 'mensagem':
                    remetente = pacote['remetente']
                    msg_cifrada_hex = pacote['conteudo']
                    chave_cifrada_b64 = pacote['chave_sessao']
                    assinatura_b64 = pacote['assinatura']

                    print(f"\n{'='*10} NOVA MENSAGEM DE {remetente} {'='*10}")
                    
                    # 1. Decifrar a Chave Twofish (Confidencialidade)
                    try:
                        chave_twofish = minhas_chaves.decrypt_key_with_rsa(chave_cifrada_b64)
                    except Exception as e:
                        print(f"[ERRO] Não foi possível decifrar a chave de sessão: {e}")
                        continue

                    # 2. Decifrar a Mensagem (Confidencialidade)
                    try:
                        twofish_obj = minhas_chaves.get_twofish(chave_twofish)
                        msg_bytes = binascii.unhexlify(msg_cifrada_hex)
                        texto_plano_bytes = twofish_obj.decrypt(msg_bytes)
                        # O padding já foi verificado dentro do Twofish (Integridade 1)
                    except Exception as e:
                        print(f"[ERRO] Falha na decifragem da mensagem: {e}")
                        continue

                    # 3. Verificar Assinatura Digital (Autenticidade e Não Repúdio)
                    if remetente in chaves_publicas_dos_pares:
                        pub_key_remetente_str = chaves_publicas_dos_pares[remetente]
                        pub_key_remetente = minhas_chaves.import_public_key(pub_key_remetente_str)
                        
                        is_autentico = minhas_chaves.verify_signature(
                            texto_plano_bytes, # Verifica assinatura contra o texto original
                            assinatura_b64, 
                            pub_key_remetente
                        )

                        if is_autentico:
                            print(f"✅ [VALIDADO] Assinatura Digital Correta (Autenticidade Garantida)")
                            print(f"💬 MENSAGEM: {texto_plano_bytes.decode('utf-8')}")
                        else:
                            print(f"❌ [ALERTA] ASSINATURA INVÁLIDA! MENSAGEM PODE TER SIDO FALSIFICADA.")
                    else:
                        print(f"[AVISO] Chave pública de {remetente} desconhecida. Não foi possível validar assinatura.")
                    
                    print("="*40 + "\n")

    except Exception as e:
        print(f"[ERRO FATAL] Loop de recebimento quebrou: {e}")
    finally:
        s.close()

def iniciar_cliente():
    global meu_nome, minhas_chaves
    
    print("--- SECURE CHAT CLIENT ---")
    meu_nome = input("Digite seu nome de usuário: ").strip()

    # Inicia a classe que criamos (gera os prints de geração de chave RSA)
    minhas_chaves = RSA_Twofish(verbose=True)

    cliente_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        cliente_socket.connect(('127.0.0.1', 9999))
    except ConnectionRefusedError:
        print("[ERRO] Servidor offline.")
        return

    # Handshake inicial (Envia nome e chave pública)
    dados_iniciais = {
        'nome': meu_nome,
        'chave_publica': minhas_chaves.export_public_key()
    }
    cliente_socket.sendall((json.dumps(dados_iniciais) + "\n").encode('utf-8'))

    # Inicia threads
    t_recv = threading.Thread(target=receber_mensagens, args=(cliente_socket,), daemon=True)
    t_send = threading.Thread(target=enviar_mensagens, args=(cliente_socket,), daemon=True)
    
    t_recv.start()
    t_send.start()

    # Loop principal para manter o script rodando
    try:
        while t_recv.is_alive() and t_send.is_alive():
            pass
    except KeyboardInterrupt:
        print("\nSaindo...")
        cliente_socket.close()

if __name__ == "__main__":
    iniciar_cliente()