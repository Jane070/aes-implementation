/*
 * Name: Jiaxin Zhang
 * Student Number: D23127255
 */
#include "rijndael.h"

#include <stdio.h>
#include <stdlib.h>

// AES S-box
unsigned char sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16};

// AES Inverse S-box
unsigned char rsbox[256] = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e,
    0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32,
    0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49,
    0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50,
    0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05,
    0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41,
    0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8,
    0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b,
    0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59,
    0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d,
    0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63,
    0x55, 0x21, 0x0c, 0x7d};
// Round constants for AES key expansion
unsigned char Rcon[32] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97,
    0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
};
// Retrieves a value from the S-box
unsigned char getSBoxValue(unsigned char num) { return sbox[num]; }
// Retrieves a value from the inverse S-box
unsigned char getSBoxInvert(unsigned char num) { return rsbox[num]; }
// Retrieves a round constant value by its index
unsigned char getRconValue(unsigned char num) { return Rcon[num]; }

// Multiplication in the Galois Field
unsigned char gmul(unsigned char rhs, unsigned char lhs) {
  unsigned char peasant = 0;
  unsigned int irreducible = 0x11b;
  while (lhs) {
    if (lhs & 1) {
      peasant = peasant ^ rhs;
    }
    if (rhs & 0x80) {
      rhs = (rhs << 1) ^ irreducible;

    } else {
      rhs = rhs << 1;
    }
    lhs = lhs >> 1;
  }
  return peasant;
}

// substitute each byte in the block with its corresponding value in the S-box.
void sub_bytes(unsigned char *block) {
  int i;

  for (i = 0; i < 16; i++) block[i] = getSBoxValue(block[i]);
}

// Cyclically shifts row n in the state by n bytes
void shift_rows(unsigned char *block) {
  unsigned char temp_block[16];

  for (int i = 0; i < 16; i += 4) {
    // First row remains unchanged
    temp_block[i] = block[i];
    temp_block[i + 1] = block[(i + 5) % 16];
    temp_block[i + 2] = block[(i + 10) % 16];
    temp_block[i + 3] = block[(i + 15) % 16];
  }

  for (int i = 0; i < 16; i++) {
    // Copy the shifted bytes back to the original block.
    block[i] = temp_block[i];
  }
}

void mix_columns(unsigned char *block) {
  unsigned char temp_block[16];

  for (int i = 0; i < 16; i += 4) {
    // Apply Galois field multiplication and XOR to mix the columns.
    temp_block[i] = gmul(block[i], (unsigned char)2) ^
                    gmul(block[i + 1], (unsigned char)3) ^ block[i + 2] ^
                    block[i + 3];
    temp_block[i + 1] = block[i] ^ gmul(block[i + 1], (unsigned char)2) ^
                        gmul(block[i + 2], (unsigned char)3) ^ block[i + 3];
    temp_block[i + 2] = block[i] ^ block[i + 1] ^
                        gmul(block[i + 2], (unsigned char)2) ^
                        gmul(block[i + 3], (unsigned char)3);
    temp_block[i + 3] = gmul(block[i], (unsigned char)3) ^ block[i + 1] ^
                        block[i + 2] ^ gmul(block[i + 3], (unsigned char)2);
  }

  for (int i = 0; i < 16; i++) {
    // Copy the mixed columns back to the original block.
    block[i] = temp_block[i];
  }
}

void invert_sub_bytes(unsigned char *block) {
  int i;
  // Replace each byte of the block with its equivalent in the inverse S-box for
  // decryption.
  for (i = 0; i < 16; i++) block[i] = getSBoxInvert(block[i]);
}

void invert_shift_rows(unsigned char *block) {
  unsigned char temp_block[16];

  // Reverse the operation of shift_rows
  for (int i = 0; i < 16; i += 4) {
    // Shift back by doing the opposite of the original function
    temp_block[i] = block[i];
    temp_block[(i + 5) % 16] = block[i + 1];
    temp_block[(i + 10) % 16] = block[i + 2];
    temp_block[(i + 15) % 16] = block[i + 3];
  }

  // Copy the inverted block back to the original block
  for (int i = 0; i < 16; i++) {
    block[i] = temp_block[i];
  }
}
// Reverses column mixing to retrieve the original column data
void invert_mix_columns(unsigned char *block) {
  unsigned char temp_block[16];

  for (int i = 0; i < 16; i += 4) {
    temp_block[i] = gmul(block[i], (unsigned char)0x0e) ^
                    gmul(block[i + 1], (unsigned char)0x0b) ^
                    gmul(block[i + 2], (unsigned char)0x0d) ^
                    gmul(block[i + 3], (unsigned char)0x09);
    temp_block[i + 1] = gmul(block[i], (unsigned char)0x09) ^
                        gmul(block[i + 1], (unsigned char)0x0e) ^
                        gmul(block[i + 2], (unsigned char)0x0b) ^
                        gmul(block[i + 3], (unsigned char)0x0d);
    temp_block[i + 2] = gmul(block[i], (unsigned char)0x0d) ^
                        gmul(block[i + 1], (unsigned char)0x09) ^
                        gmul(block[i + 2], (unsigned char)0x0e) ^
                        gmul(block[i + 3], (unsigned char)0x0b);
    temp_block[i + 3] = gmul(block[i], (unsigned char)0x0b) ^
                        gmul(block[i + 1], (unsigned char)0x0d) ^
                        gmul(block[i + 2], (unsigned char)0x09) ^
                        gmul(block[i + 3], (unsigned char)0x0e);
  }

  for (int i = 0; i < 16; i++) {
    block[i] = temp_block[i];
  }
}

// Rotates the bytes of a 4-byte word to the left by one position.
void rotate(unsigned char *word) {
  unsigned char c = word[0];
  for (int i = 0; i < 3; i++) {
    word[i] = word[i + 1];
  }
  word[3] = c;
}

void core(unsigned char *word, int iteration) {
  // Rotate the 32-bit word 8 bits to the left
  rotate(word);
  // Apply S-Box substitution on all 4 parts of the 32-bit word
  for (int i = 0; i < 4; ++i) {
    word[i] = getSBoxValue(word[i]);
  }
  // XOR the output of the rcon operation with iteration to the first part
  // (leftmost) only
  word[0] = word[0] ^ getRconValue(iteration);
}

void add_round_key(unsigned char *block, unsigned char *round_key) {
  int i;
  for (i = 0; i < 16; i++) block[i] = block[i] ^ round_key[i];
}

// Expands the 128-bit key into 176 bytes for the AES key schedule
unsigned char *expand_key(unsigned char *cipher_key) {
  // Allocate memory for the expanded key
  unsigned char *expandedKey = malloc(EXPANDED_KEY_SIZE);
  if (!expandedKey) return NULL;

  int currentSize = 0;
  int rconIteration = 1;
  unsigned char t[4];  // Temporary storage for core function

  // Copy the initial key as the beginning of the expanded key
  for (int i = 0; i < BLOCK_SIZE; i++) {
    expandedKey[i] = cipher_key[i];
  }
  currentSize += BLOCK_SIZE;
  // Continue expanding the key until all 176 bytes are created
  while (currentSize < EXPANDED_KEY_SIZE) {
    // Read the last 4 bytes of the current expanded key into t
    for (int i = 0; i < 4; i++) {
      t[i] = expandedKey[currentSize - 4 + i];
    }

    if (currentSize % BLOCK_SIZE == 0) {
      core(t, rconIteration++);
    }

    // XOR t with the 4-byte block 16 bytes before the end of the current
    // expanded key
    for (int i = 0; i < 4; i++) {
      expandedKey[currentSize] = expandedKey[currentSize - BLOCK_SIZE] ^ t[i];
      currentSize++;
    }
  }

  return expandedKey;
}

// Encrypts a single 16-byte block using the AES algorithm
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  // Allocate memory for the output cipher block
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  // Ensure memory allocation was successful
  if (!output) return NULL;

  unsigned char *expandedKey = expand_key(key);

  // Ensure key expansion was successful
  if (!expandedKey) {
    free(output);
    return NULL;
  }

  // Copy the plaintext into the output buffer to start the encryption process
  for (int i = 0; i < BLOCK_SIZE; i++) {
    output[i] = plaintext[i];
  }

  // Initial round of adding the round key to the plaintext
  add_round_key(output, expandedKey);

  // Perform 9 rounds of the AES encryption process
  for (int round = 1; round < 10; round++) {
    sub_bytes(output);

    shift_rows(output);

    mix_columns(output);

    add_round_key(output, expandedKey + (BLOCK_SIZE * round));
  }

  // Final round: No MixColumns
  sub_bytes(output);

  shift_rows(output);

  add_round_key(output,
                expandedKey + (BLOCK_SIZE * 10));  // 160 = BLOCK_SIZE * 10

  // Free the expanded key as it's no longer needed
  free(expandedKey);

  return output;
}

// Decrypts a single 16-byte block using the AES algorithm
unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // Allocate memory for the plaintext
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);

  if (!output) return NULL;
  // Expand the key for AES
  unsigned char *expandedKey = expand_key(key);
  if (!expandedKey) {
    free(output);
    return NULL;
  }

  // Copy the ciphertext into the output buffer to start the decryption process
  for (int i = 0; i < BLOCK_SIZE; i++) {
    output[i] = ciphertext[i];
  }

  // Perform the final round first for decryption without invMixColumns
  add_round_key(output, expandedKey + 160);
  invert_shift_rows(output);
  invert_sub_bytes(output);

  // Perform the remaining 9 rounds in reverse order
  for (int round = 9; round > 0; round--) {
    add_round_key(output, expandedKey + (BLOCK_SIZE * round));
    invert_mix_columns(output);
    invert_shift_rows(output);
    invert_sub_bytes(output);
  }

  // Initial round key addition
  add_round_key(output, expandedKey);

  // Free the expanded key as it's no longer needed
  free(expandedKey);

  return output;
}
