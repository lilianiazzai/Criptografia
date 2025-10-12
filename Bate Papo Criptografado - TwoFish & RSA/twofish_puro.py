import hashlib
import os

class Twofish:
    """
    Implementação simplificada e compatível da interface Twofish,
    feita 100% em Python puro (sem bibliotecas externas).
    
    ⚠️ IMPORTANTE:
    - Esta versão NÃO é uma implementação real do algoritmo Twofish.
    - Ela é apenas uma simulação leve que mantém a interface compatível
      com o resto do código (crypto_hibrido.py e client/server).
    - Serve para fins de teste, demonstração e integração.
    """

    def __init__(self, key: bytes):
        # Garante que a chave tenha um tamanho fixo (16 bytes)
        self.key = hashlib.sha256(key).digest()[:16]

    def pad(self, data: bytes) -> bytes:
        """Aplica padding estilo PKCS#7 para múltiplos de 16 bytes."""
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    def unpad(self, data: bytes) -> bytes:
        """Remove o padding PKCS#7 aplicado no final."""
        pad_len = data[-1]
        if pad_len < 1 or pad_len > 16:
            raise ValueError("Dados corrompidos: padding inválido.")
        return data[:-pad_len]

    def _xor_bytes(self, a: bytes, b: bytes) -> bytes:
        """Operação XOR byte a byte (simula mistura de chave)."""
        return bytes(x ^ y for x, y in zip(a, b))

    def encrypt(self, plaintext: bytes) -> bytes:
        """Criptografa (simulado) usando XOR e uma derivação da chave."""
        plaintext = self.pad(plaintext)
        keystream = hashlib.sha256(self.key).digest() * (len(plaintext) // 32 + 1)
        ciphertext = self._xor_bytes(plaintext, keystream[:len(plaintext)])
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Descriptografa (simulado) revertendo o XOR."""
        keystream = hashlib.sha256(self.key).digest() * (len(ciphertext) // 32 + 1)
        plaintext_padded = self._xor_bytes(ciphertext, keystream[:len(ciphertext)])
        return self.unpad(plaintext_padded)
