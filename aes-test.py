import unittest
import ctypes
import secrets
from aes.aes import AES  # 替换成你的Python AES模块

# 假设你的C库名称为 libaes.so (Linux) 或 libaes.dll (Windows)
c_aes = ctypes.CDLL('./rijndael.so')

class TestAESEncryptionDecryption(unittest.TestCase):

    def test_encryption_decryption(self):
        

        plaintext = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
        key_buffer = bytes([50, 20, 46, 86, 67, 9, 70, 27, 75, 17, 51, 17, 4,  8, 6, 99])
        # Python
        aes_python = AES(key_buffer)
        encrypted_bytes_py = aes_python.encrypt_block(plaintext)

        # C
        c_aes.aes_encrypt_block.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        c_aes.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)
        c_aes.aes_decrypt_block.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
        c_aes.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)

        encrypted_c = c_aes.aes_encrypt_block(ctypes.c_char_p(plaintext), ctypes.c_char_p(key_buffer))
        encrypted_bytes_c = bytes(encrypted_c.contents)

        print("Encrypted with Python:", encrypted_bytes_py.hex())
        print("Encrypted with C:", encrypted_bytes_c.hex())
        self.assertEqual(encrypted_bytes_c, encrypted_bytes_py)
       
if __name__ == '__main__':
    unittest.main()