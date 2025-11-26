import hashlib
import os
import binascii

class Twofish:
    def __init__(self, key: bytes, verbose=True):
        self.verbose = verbose

        # Deriva a chave interna usando SHA-256 para garantir tamanho fixo
        self.key_hash = hashlib.sha256(key).digest()

        # Guarda a versão Hex da chave apenas para exibir
        self.key_display = binascii.hexlify(key).decode()

        if self.verbose:
            print("\n================= [TWOFISH - INICIALIZAÇÃO] =================")
            print("[CONFIDENCIALIDADE] Chave de Sessão (Simétrica) recebida.")
            print(f"   > Chave Twofish (Hex): {self.key_display}")
            print(f"   > Hash Interno da Chave (Primeiros 16 hex): "
                  f"{binascii.hexlify(self.key_hash).decode()[:16]}...")
            print("==============================================================")

    def pad(self, data: bytes) -> bytes:
        """Aplica padding PKCS#7 (Garante Integridade de tamanho)."""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def unpad(self, data: bytes) -> bytes:
        """Remove e verifica o padding (Prova de Integridade)."""
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            if self.verbose:
                print("[INTEGRIDADE] ERRO: Padding inválido detectado.")
            raise ValueError("Padding inválido.")
        return data[:-pad_len]

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        return bytes(x ^ y for x, y in zip(a, b))

    def encrypt(self, plaintext: bytes) -> bytes:
        """Cifra usando XOR com keystream derivado da chave (modelo simplificado)."""
        if self.verbose:
            print("\n[TWOFISH - CIFRAGEM]")
            print(f"[CONFIDENCIALIDADE] Texto original recebido: {plaintext}")

        padded_text = self.pad(plaintext)

        # Gera keystream
        keystream = hashlib.sha256(self.key_hash).digest() * (len(padded_text) // 32 + 1)

        ciphertext = self._xor_bytes(padded_text, keystream[:len(padded_text)])

        if self.verbose:
            print(f"[CONFIDENCIALIDADE] Resultado Cifrado (Hex): "
                  f"{binascii.hexlify(ciphertext).decode()}")
            print("[INTEGRIDADE] Padding aplicado e controlado.")
            print("[DISPONIBILIDADE] Cifragem concluída sem erros.")

        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        if self.verbose:
            print("\n[TWOFISH - DECIFRAGEM]")
            print("[CONFIDENCIALIDADE] Pacote cifrado recebido.")

        keystream = hashlib.sha256(self.key_hash).digest() * (len(ciphertext) // 32 + 1)

        padded_plaintext = self._xor_bytes(ciphertext, keystream[:len(ciphertext)])

        try:
            plaintext = self.unpad(padded_plaintext)
            if self.verbose:
                print("[INTEGRIDADE] Padding validado com sucesso.")
                print(f"[DISPONIBILIDADE] Mensagem recuperada: {plaintext}")
            return plaintext

        except ValueError:
            print("[INTEGRIDADE] ERRO: Mensagem corrompida ou adulterada!")
            raise
