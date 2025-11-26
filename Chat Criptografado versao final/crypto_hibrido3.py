from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

from twofish_puro2 import Twofish
import os
import base64
import binascii

class RSA_Twofish:
    def __init__(self, verbose=True):
        self.verbose = verbose

        if self.verbose:
            print("\n" + "="*60)
            print("[RSA] Inicializando Módulo de Criptografia Híbrida")
            print("[DISPONIBILIDADE] Gerando par de chaves RSA (2048 bits)...")

        # Geração das chaves RSA
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
        self.private_key = self.rsa_key

        if self.verbose:
            print("[AUTENTICIDADE] Chave Pública gerada com sucesso.")
            pub_short = self.public_key.export_key().decode()[:120]
            print("--> Início da Chave Pública:")
            print(pub_short + "...")
            print("="*60 + "\n")

    # =====================================================
    # EXPORTAÇÃO E IMPORTAÇÃO DAS CHAVES PÚBLICAS
    # =====================================================
    def export_public_key(self):
        """Exporta chave pública em Base64 para transporte seguro."""
        pem_bytes = self.public_key.export_key()
        return base64.b64encode(pem_bytes).decode('utf-8')

    def import_public_key(self, pubkey_b64_string):
        """Importa chave pública Base64 de outro usuário."""
        try:
            pem_bytes = base64.b64decode(pubkey_b64_string)
            return RSA.import_key(pem_bytes)
        except Exception:
            print("[ERRO] Falha ao importar chave pública.")
            return None

    # =====================================================
    # CRIPTOGRAFIA DA CHAVE SIMÉTRICA (RSA-OAEP)
    # =====================================================
    def encrypt_key_with_rsa(self, twofish_key, pubkey_dest):
        """
        Encripta a chave Twofish com RSA-OAEP.
        Isso garante:
        - CONFIDENCIALIDADE (somente o dono da chave privada abre)
        - AUTENTICIDADE (chave pública do destinatário é usada corretamente)
        """
        if self.verbose:
            print("\n[RSA] Iniciando encapsulamento de chave Twofish...")
            print("[CONFIDENCIALIDADE] Chave Twofish Original (Hex):",
                  binascii.hexlify(twofish_key).decode())

        try:
            cipher_rsa = PKCS1_OAEP.new(pubkey_dest)
            encrypted_key = cipher_rsa.encrypt(twofish_key)
        except Exception as e:
            print("[ERRO] Falha ao criptografar chave Twofish:", e)
            raise

        if self.verbose:
            enc_hex = binascii.hexlify(encrypted_key).decode()[:80]
            print("[CONFIDENCIALIDADE] Envelope Digital (cifrado RSA):", enc_hex, "...")
            print("[INTEGRIDADE] RSA-OAEP protege contra adulterações do envelope.")

        return base64.b64encode(encrypted_key).decode('utf-8')

    # =====================================================
    # DECIFRAGEM DA CHAVE SIMÉTRICA
    # =====================================================
    def decrypt_key_with_rsa(self, encrypted_key_b64):
        """Abre o envelope digital usando a chave privada."""
        encrypted_key = base64.b64decode(encrypted_key_b64)

        if self.verbose:
            print("\n[RSA] Abrindo Envelope Digital recebido...")
            print("[CONFIDENCIALIDADE] Chave RSA PRIVADA agora usada para decifrar.")

        try:
            cipher_rsa = PKCS1_OAEP.new(self.private_key)
            twofish_key = cipher_rsa.decrypt(encrypted_key)
        except Exception as e:
            print("[ERRO] Falha ao decifrar chave de sessão:", e)
            raise

        if self.verbose:
            print("[CONFIDENCIALIDADE] Chave de Sessão recuperada (Hex):",
                  binascii.hexlify(twofish_key).decode())
            print("[INTEGRIDADE] Envelope aberto sem modificações detectadas.")

        return twofish_key

    # =====================================================
    # ASSINATURA DIGITAL (NÃO-REPÚDIO)
    # =====================================================
    def sign_message(self, message: bytes):
        """
        Assina a mensagem com RSA (chave privada), garantindo:
        - AUTENTICIDADE (foi o usuário mesmo)
        - NÃO-REPÚDIO (não pode negar que enviou)
        - INTEGRIDADE (assina o hash da mensagem)
        """
        h = SHA256.new(message)
        signature = pkcs1_15.new(self.private_key).sign(h)

        if self.verbose:
            #print("\n[RSA - NÃO-REPÚDIO] Assinatura digital criada.")
            print(f"[NÃO-REPÚDIO] Hash SHA-256 gerado na origem: {h.hexdigest()}")
            print("[AUTENTICIDADE] Hash assinado com a chave PRIVADA do remetente.")
            print("[INTEGRIDADE] SHA-256 protege contra alteração da mensagem.")

        return base64.b64encode(signature).decode('utf-8')

    # =====================================================
    # VERIFICAÇÃO DA ASSINATURA DIGITAL
    # =====================================================
    def verify_signature(self, message: bytes, signature_b64, pubkey_sender):
        """
        Verifica assinatura digital:
        - AUTENTICIDADE (confirma remetente)
        - NÃO-REPÚDIO (só ele tem a chave privada)
        - INTEGRIDADE (garante que não houve alteração)
        """
        signature = base64.b64decode(signature_b64)
        h = SHA256.new(message)

        try:
            pkcs1_15.new(pubkey_sender).verify(h, signature)
            if self.verbose:
                print("[AUTENTICIDADE] Assinatura CONFIRMADA.")
                print("[INTEGRIDADE] Mensagem íntegra e sem alterações.")
                print("[NÃO-REPÚDIO] Remetente NÃO pode negar envio.")
            return True

        except Exception:
            print("[ALERTA] Assinatura digital inválida! Mensagem adulterada ou remetente falso.")
            return False

    # =====================================================
    # HELPERS DO TWOFISH
    # =====================================================
    def get_twofish(self, key):
        return Twofish(key)

    def generate_twofish_key(self):
        """Gera chave simétrica de sessão."""
        key = os.urandom(16)
        if self.verbose:
            print("\n[SISTEMA] Nova chave Twofish de sessão gerada.")
            print("[CONFIDENCIALIDADE] Chave será usada só nesta mensagem.")
        return key
