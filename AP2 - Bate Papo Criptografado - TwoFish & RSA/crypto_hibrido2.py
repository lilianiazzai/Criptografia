from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
from twofish_puro2 import Twofish  # Importa sua classe Twofish criada anteriormente
import os
import base64
import binascii

class RSA_Twofish:
    def __init__(self, verbose=True):
        self.verbose = verbose
        if self.verbose:
            print("\n" + "="*50)
            print("[RSA] Inicializando Módulo de Criptografia Híbrida...")
            print("[DISPONIBILIDADE] Gerando par de chaves RSA 2048 bits...")
        
        # Gera o par de chaves RSA (pública e privada)
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
        self.private_key = self.rsa_key
        
        if self.verbose:
            pub_pem = self.public_key.export_key().decode()
            print(f"[AUTENTICIDADE] Chave Pública Gerada (Início): {pub_pem[27:90]}...")
            print("="*50 + "\n")

    # === Exporta/importa a chave pública ===
    def export_public_key(self):
        """Exporta a chave pública em base64 (segura para JSON)."""
        pem_bytes = self.public_key.export_key()
        return base64.b64encode(pem_bytes).decode('utf-8')

    def import_public_key(self, pubkey_b64_string):
        """Importa a chave pública de outro usuário a partir de base64."""
        pem_bytes = base64.b64decode(pubkey_b64_string)
        return RSA.import_key(pem_bytes)

    # === Criptografa/decifra a chave simétrica (Envelope Digital) ===
    def encrypt_key_with_rsa(self, twofish_key, pubkey_dest):
        """
        Criptografa a chave Twofish com a chave pública do destinatário.
        Isso garante a CONFIDENCIALIDADE da troca de chaves.
        """
        if self.verbose:
            print(f"\n[RSA - CONFIDENCIALIDADE] Encapsulando chave Twofish para envio...")
            print(f"   > Chave Twofish Original: {binascii.hexlify(twofish_key).decode()}")

        cipher_rsa = PKCS1_OAEP.new(pubkey_dest)
        encrypted_key = cipher_rsa.encrypt(twofish_key)
        
        if self.verbose:
            print(f"   > Chave Cifrada (Envelope Digital): {binascii.hexlify(encrypted_key).decode()[:50]}...")
        
        return base64.b64encode(encrypted_key).decode('utf-8')

    def decrypt_key_with_rsa(self, encrypted_key_b64):
        """
        Decifra a chave Twofish recebida usando a Própria Chave Privada.
        """
        encrypted_key = base64.b64decode(encrypted_key_b64)
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        
        twofish_key = cipher_rsa.decrypt(encrypted_key)
        
        if self.verbose:
            print(f"\n[RSA - CONFIDENCIALIDADE] Envelope Digital aberto.")
            print(f"   > Chave Twofish Recuperada: {binascii.hexlify(twofish_key).decode()}")
            
        return twofish_key

    # === ASSINATURA DIGITAL (Prova de Autenticidade e Não Repúdio) ===
    def sign_message(self, message: bytes):
        """
        Assina o hash da mensagem com a chave PRIVADA.
        Prova que fui EU quem mandou (Autenticidade) e impede negação (Não Repúdio).
        """
        h = SHA256.new(message)
        signature = pkcs1_15.new(self.private_key).sign(h)
        
        if self.verbose:
            print(f"[RSA - NÃO REPÚDIO] Assinatura Digital gerada para a mensagem.")
            
        return base64.b64encode(signature).decode('utf-8')

    def verify_signature(self, message: bytes, signature_b64, pubkey_sender):
        """
        Verifica a assinatura usando a chave PÚBLICA do remetente.
        Garante a INTEGRIDADE (mensagem não mudou) e AUTENTICIDADE (foi ele quem mandou).
        """
        signature = base64.b64decode(signature_b64)
        h = SHA256.new(message)
        try:
            pkcs1_15.new(pubkey_sender).verify(h, signature)
            if self.verbose:
                print(f"[RSA - AUTENTICIDADE] Assinatura Válida! Remetente confirmado.")
            return True
        except (ValueError, TypeError):
            print(f"[ERRO] Assinatura Inválida! Possível ataque detectado.")
            return False

    # === Helpers Twofish ===
    def get_twofish(self, key):
        """Cria o objeto Twofish com a chave já decifrada."""
        return Twofish(key)

    def generate_twofish_key(self):
        """Gera uma nova chave Twofish de 16 bytes."""
        key = os.urandom(16)
        if self.verbose:
            print(f"[SISTEMA] Nova chave de sessão aleatória gerada.")
        return key