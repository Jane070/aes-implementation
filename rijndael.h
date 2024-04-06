/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 *
 * Name: Jiaxin Zhang
 * Student Number: D23127255
 */

#ifndef RIJNDAEL_H
#define RIJNDAEL_H

#define BLOCK_ACCESS(block, row, col) (block[(row * 4) + col])
#define BLOCK_SIZE 16
#define EXPANDED_KEY_SIZE \
  176  // For 128-bit keys, the expanded key size is 176 bytes

unsigned char getSBoxValue(unsigned char num);

/*
 * These should be the main encrypt/decrypt functions (i.e. the main
 * entry point to the library for programmes hoping to use it to
 * encrypt or decrypt data)
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key);
unsigned char *aes_decrypt_block(unsigned char *ciphertext, unsigned char *key);

#endif
