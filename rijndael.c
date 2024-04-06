/*
 * TODO: Add your name and student number here, along with
 *       a brief description of this code.
 * Name: Jiaxin Zhang
 * Student Number: D23127255
 *
 *
 */

#include <stdlib.h>
// TODO: Any other files you need to include should go here

#include "rijndael.h"

/*
 * Operations used when encrypting a block
 */
void sub_bytes(unsigned char *block) {
  // TODO: Implement me!
  int i;
  /* substitute all the values from the state with the value in the SBox
   * using the state value as index for the SBox
   */
  for (i = 0; i < 16; i++) block[i] = getSBoxValue(state[i]);
}

void shift_rows(unsigned char *block) {
  // TODO: Implement me!
  int i;
  /* iterate over the 4 rows and call shiftRow() with that row */
  for (i = 0; i < 4; i++) shiftRow(block + i * 4, i);
}

void shiftRow(unsigned char *state, unsigned char nbr) {
  int i, j;
  unsigned char tmp;
  /* each iteration shifts the row to the left by 1 */
  for (i = 0; i < nbr; i++) {
    tmp = state[0];
    for (j = 0; j < 3; j++) state[j] = state[j + 1];
    state[3] = tmp;
  }
}

void mix_columns(unsigned char *block) {
  // TODO: Implement me!
}

/*
 * Operations used when decrypting a block
 */
void invert_sub_bytes(unsigned char *block) {
  // TODO: Implement me!
}

void invert_shift_rows(unsigned char *block) {
  // TODO: Implement me!
}

void invert_mix_columns(unsigned char *block) {
  // TODO: Implement me!
}

/*
 * This operation is shared between encryption and decryption
 */
void add_round_key(unsigned char *block, unsigned char *round_key) {
  // TODO: Implement me!
}

/*
 * This function should expand the round key. Given an input,
 * which is a single 128-bit key, it should return a 176-byte
 * vector, containing the 11 round keys one after the other
 */
unsigned char *expand_key(unsigned char *cipher_key) {
  // TODO: Implement me!
  return 0;
}

/*
 * The implementations of the functions declared in the
 * header file should go here
 */
unsigned char *aes_encrypt_block(unsigned char *plaintext, unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  return output;
}

unsigned char *aes_decrypt_block(unsigned char *ciphertext,
                                 unsigned char *key) {
  // TODO: Implement me!
  unsigned char *output =
      (unsigned char *)malloc(sizeof(unsigned char) * BLOCK_SIZE);
  return output;
}
