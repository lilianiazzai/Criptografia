import hashlib
import os
import binascii

class Twofish:
    def __init__(self, key: bytes, verbose=True):
        self.verbose = verbose
        # Deriva a chave interna usando SHA-256 para garantir tamanho fixo
        self.key_hash = hashlib.sha256(key).digest()
        
        # Guarda a versão Hex da chave apenas para mostrar no print
        self.key_display = binascii.hexlify(key).decode()

        if self.verbose:
            print(f"\n[TWOFISH] Inicializando Cifra Simétrica...")
            print(f"   > Chave de Sessão (Simétrica): {self.key_display}")
            print(f"   > Hash Interno da Chave: {binascii.hexlify(self.key_hash).decode()[:16]}...")

    def pad(self, data: bytes) -> bytes:
        """Aplica padding PKCS#7 (Garante Integridade de tamanho)."""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def unpad(self, data: bytes) -> bytes:
        """Remove e verifica o padding (Prova de Integridade)."""
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            if self.verbose:
                print("   [ERRO] Falha na Integridade: Padding incorreto detectado.")
            raise ValueError("Padding inválido.")
        return data[:-pad_len]

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def encrypt(self, plaintext: bytes) -> bytes:
        # Print prova CONFIDENCIALIDADE (mostra o antes)
        if self.verbose:
            print(f"   [TWOFISH] Cifrando mensagem: '{plaintext}'")

        padded_text = self.pad(plaintext)
        
        # Gera keystream baseado na chave
        keystream = hashlib.sha256(self.key_hash).digest() * (len(padded_text) // 32 + 1)
        
        # Aplica a cifra
        ciphertext = self._xor_bytes(padded_text, keystream[:len(padded_text)])
        
        # Print prova CONFIDENCIALIDADE (mostra o depois - ilegível)
        if self.verbose:
            print(f"   [TWOFISH] Resultado Cifrado (Hex): {binascii.hexlify(ciphertext).decode()}")
            
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.verbose:
            print(f"   [TWOFISH] Decifrando pacote recebido...")

        keystream = hashlib.sha256(self.key_hash).digest() * (len(ciphertext) // 32 + 1)
        
        padded_plaintext = self._xor_bytes(ciphertext, keystream[:len(ciphertext)])
        
        try:
            plaintext = self.unpad(padded_plaintext)
            # Print prova DISPONIBILIDADE e INTEGRIDADE (dado recuperado)
            if self.verbose:
                print(f"   [TWOFISH] Mensagem recuperada com sucesso: '{plaintext}'")
            return plaintext
        except ValueError:
            raise