import unittest
import ctypes
import secrets
import aes.aes as aes
from aes.aes import AES  


c_aes = ctypes.CDLL('./rijndael.so')

class TestAESEncryptionDecryption(unittest.TestCase):

    def test_encryption_decryption(self):
        

        for _ in range(3):  # Generate 3 pairs of key and plaintext, test encryption and decryption
            # Generate 3 pairs of key and plaintext
            key_buffer = secrets.token_bytes(16)
            plaintext_buffer = secrets.token_bytes(16)

            # Set parameters and return type for C function
            c_aes.aes_encrypt_block.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            c_aes.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)
            c_aes.aes_decrypt_block.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
            c_aes.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_char * 16)

            # encryption：C implementation
            encrypted_c = c_aes.aes_encrypt_block(ctypes.c_char_p(plaintext_buffer), ctypes.c_char_p(key_buffer))
            encrypted_bytes_c = bytes(encrypted_c.contents)

            # encryption：Python implementation
            aes_python = AES(key_buffer)
            encrypted_bytes_py = aes_python.encrypt_block(plaintext_buffer)

            # Check whether the encryption results of the two implementations are the same
            self.assertEqual(encrypted_bytes_c, encrypted_bytes_py)

            # decryption：C implementation
            decrypted_c = c_aes.aes_decrypt_block(ctypes.c_char_p(encrypted_bytes_c), ctypes.c_char_p(key_buffer))
            decrypted_bytes_c = bytes(decrypted_c.contents)

            # decryption：Python implementation
            decrypted_bytes_py = aes_python.decrypt_block(encrypted_bytes_py)
            
            # Check decryption is successful
            self.assertEqual(decrypted_bytes_c, plaintext_buffer)
            self.assertEqual(decrypted_bytes_py, plaintext_buffer)
       
if __name__ == '__main__':
    unittest.main()