#ifndef MODES_H
#define MODES_H
#include <stdio.h>

void XOR_blocks(unsigned char* block_1, unsigned char* block_2, int tsize);
void state_to_64int(unsigned char* block, unsigned long long int res[2]);
void int64_to_state(unsigned char* block, unsigned long long int res[2]);
void mult_F128(unsigned long long int b1[2], unsigned long long int b2[2]);
void precompute_F128(unsigned long long int b[2], unsigned long long int res[256]);
void fast_mult_F128(unsigned long long int b[2], unsigned long long int res[2], unsigned long long int precomp[256]);
void incr(unsigned char* counter);
void associate(unsigned char* block1, unsigned char* block2) ;

void ECB_mode(unsigned char** text, int nblock, unsigned char* key, int key_size);
void inv_ECB_mode(unsigned char** text, int nblock, unsigned char* key, int key_size);

void CBC_mode(unsigned char** text, int nblock, unsigned char* key, int key_size, unsigned char* init);
void inv_CBC_mode(unsigned char** text, int nblock, unsigned char* key, int key_size, unsigned char* init);

void CFB_mode(unsigned char** text, int nblock, int tsize, unsigned char* key, int key_size, unsigned char* init);
void inv_CFB_mode(unsigned char** text, int nblock, int tsize, unsigned char* key, int key_size, unsigned char* init);

void GCM_mode(unsigned char** text, int nblock, unsigned char* key, int key_size, unsigned char* authtag, unsigned char* authdata, unsigned char* IV, long long int lenA, long long int lenC);
void inv_GCM_mode(unsigned char** text, int nblock, unsigned char* key, int key_size, unsigned char* authtag, unsigned char* authdata, unsigned char* IV, long long int lenA, long long int lenC);

#endif /* MODES_H */