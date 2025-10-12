from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from twofish_puro import Twofish
import os
import base64

class RSA_Twofish:
    def __init__(self):
        # Gera o par de chaves RSA (pública e privada)
        self.rsa_key = RSA.generate(2048)
        self.public_key = self.rsa_key.publickey()
        self.private_key = self.rsa_key

    # === Exporta/importa a chave pública em formato seguro ===
    def export_public_key(self):
        """Exporta a chave pública em base64 (segura para JSON)."""
        pem_bytes = self.public_key.export_key()
        return base64.b64encode(pem_bytes)

    def import_public_key(self, pubkey_b64_bytes):
        """Importa a chave pública a partir de uma string base64."""
        pem_bytes = base64.b64decode(pubkey_b64_bytes)
        return RSA.import_key(pem_bytes)

    # === Criptografa/decifra a chave simétrica (Twofish) ===
    def encrypt_key_with_rsa(self, twofish_key, pubkey_dest):
        """Criptografa a chave Twofish com a chave pública RSA do destinatário."""
        cipher_rsa = PKCS1_OAEP.new(pubkey_dest)
        return cipher_rsa.encrypt(twofish_key)

    def decrypt_key_with_rsa(self, encrypted_key):
        """Decifra a chave Twofish recebida."""
        cipher_rsa = PKCS1_OAEP.new(self.private_key)
        return cipher_rsa.decrypt(encrypted_key)

    # === Cria o objeto Twofish ===
    def get_twofish(self, key):
        """Cria o objeto Twofish com a chave já decifrada."""
        return Twofish(key)

    # === Gera nova chave simétrica ===
    def generate_twofish_key(self):
        """Gera uma nova chave Twofish de 16 bytes."""
        return os.urandom(16)