#ifndef CIPHER_H
#define CIPHER_H
#include <stdio.h>

int GetPowerGenerator(unsigned char c);
unsigned char FastMult(unsigned char a, unsigned char b);
void State_mult(unsigned char* state, const unsigned char* mixcol);
unsigned char GetSboxValue(unsigned char c);
int get_nround(int key_size);

void SubBytes(unsigned char* state);
void ShiftRows(unsigned char* state);
void MixColumns(unsigned char* state);
void AddRoundKey(unsigned char* state, unsigned char* expandedkey, int step);
void cipher_block(unsigned char* state, unsigned char* expkey, int Nround);

void InvShiftRows(unsigned char* state);
void InvSubBytes(unsigned char* state);
void InvMixColumns(unsigned char* state);
void decipher_block(unsigned char* state, unsigned char* expkey, int Nround);

#endif /* CIPHER_H */