#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <stdbool.h>
#include <unistd.h>
#include "../include/keyexp.h"
#include "../include/cipher.h"
#include "../include/modes.h"
#include "../include/tools.h"


/*
@param block1 and block2 : two array of unsigned char of the same size
@param size the size of block1 and block2
modify block1 so that block1 = block1 xor block2
*/

void XOR_blocks(unsigned char* block_1, unsigned char* block_2, int size) {
    int i;
    for(i = 0; i < size; i++) {
        block_1[i] ^= block_2[i];
    }
}
/*
param block a 16 unsigned char array
param res a 2 long long int array

This function transfer block into a 128 bits represntation stocked in 2 long long int (each are 64 bits)
*/
void state_to_64int(unsigned char* block, unsigned long long int res[2]) {
    int i;
    res[0] = 0;
    res[1] = 0;
    for(i = 0; i < 8; i++) {
        res[0] = res[0] | (unsigned long long int)block[i] << (56 - i * 8);
    }
    for(i = 0; i < 8; i++) {
        res[1] = res[1] | (unsigned long long int)block[i + 8] << (56 - i * 8);
    }
}

/*
This function is the reciprocal function of the previous one
*/

void int64_to_state(unsigned char* block, unsigned long long int res[2]) {
    int i;
    for(i = 0; i < 8; i++) {
        block[i] = (unsigned int)(res[0] >> ((56 - i * 8)) & 0xFF);
    }
    for(i = 0; i < 8; i++) {
        block[i + 8] = (unsigned int)(res[1] >> ((56 - i * 8)) & 0xFF);
    }
}

/*
This function multiply 2 elements of the field used in GCM mode. The result is stored in the first parameter
This function is not used in pratice
*/

void mult_F128(unsigned long long int b1[2], unsigned long long int b2[2]) {
    unsigned long long int res[2] = {0}; // result
    int i;
    int border;
    unsigned long long int remain =  0xe100000000000000; // reprentation of x^7 + x^2 + x + 1
    for(i = 0; i < 64 ; i++) {
        if((b2[0] >> (63 - i)) & 1) { // if the ith bit of b2 is one 
            res[0] ^= b1[0]; // adding b1*x^i to the result
            res[1] ^= b1[1];
        }
        border = b1[1] % 2; // checking if the last bit is 0 or 1
        b1[1] = (b1[1] >> 1) | (b1[0] << 63); // left shift of b1
        b1[0] >>= 1;
        if(border) {
            b1[0] ^= remain; // adding remain if last bit was 1
        }
    }

    for(i = 0; i < 64 ; i++) { // same process for the second part of b2
        if((b2[1] >> (63 - i)) & 1) {
            res[0] ^= b1[0];
            res[1] ^= b1[1];
        }
        border = b1[1] % 2;
        b1[1] = (b1[1] >> 1) | (b1[0] << 63);
        b1[0] >>= 1;
        if(border) {
            b1[0] ^= remain;
        }
    }

    b1[0] = res[0]; // stocking the result in b1
    b1[1] = res[1];
}


/*
This function compute all b*x^i for i in {0,..,127} and stock the result in res
*/

void precompute_F128(unsigned long long int b[2], unsigned long long int res[256]) {
    res[0] = b[0];
    res[1] = b[1];
    int border;
    int i;
    unsigned long long int remain =  0xe100000000000000;
    for(i = 1; i < 128; i++) {
        border = b[1] % 2;
        b[1] = (b[1] >> 1) | (b[0] << 63);
        b[0] >>= 1;
        if(border) {
            b[0] ^= remain; 
        }
        res[2*i] = b[0]; // add b*x^i
        res[2*i+1] = b[1];
    }
}

/*
This function is a faster multiplication for the GCM mode (5* faster as the previous one according to my tests).
It depends on a precomputation
@param b : an element of the field used in GCM represented with 2 long long int
@param res, a precomputation made to an other element b2 so that res contains all b2*x^i for i in {0,...127}
The function stock the result of b * b2 in res
We use this function because GCM always multiply by the same element.
*/

void fast_mult_F128(unsigned long long int b[2], unsigned long long int res[2], unsigned long long int precomp[256]) {
    res[0] = 0;
    res[1] = 0;
    int i;
     for(i = 0; i < 64 ; i++) {
        if((b[0] >> (63 - i)) & 1) { // if the ith bit of b is 1
            res[0] ^= precomp[2*i]; // add b2* x^i to the result
            res[1] ^= precomp[2*i + 1];
        }
    }
    for(i = 0; i < 64 ; i++) {
        if((b[1] >> (63 - i)) & 1) {
            res[0] ^= precomp[128 + 2*i];
            res[1] ^= precomp[2*i + 129];
        }
    }
}

void incr(unsigned char* counter) { // This is the function icr used in the GCM standard

    if(counter[15] == 0xFF) {// adding 1 but only to the 32 last bit part of counter
        counter[15] = 0;
        if(counter[14] == 0xFF) {
            counter[14] = 0;
            if(counter[13] == 0xFF) {
                counter[13] = 0;
                if(counter[12] == 0xFF) {
                    counter[12] = 0; 
                }
                else {
                    counter[12] += 1;
                }
            }
            else {
                counter[13] += 1;
            }
        }
        else {
            counter[14] += 1;
        }
    }
    else {
        counter[15] += 1;
    }
}
/*
@param block1 and block2 2 states
This function stock block2 into block1
*/
void associate(unsigned char* block1, unsigned char* block2) {
    for(int i = 0; i < size_block; i++) {
        block1[i] = block2[i];
    }
}

/*
@param text the text to cipher
@param nblock the number of block in text
@param key the encryption key
@param key_size the size of the key
This function use the ECB mode to encrypt text. The result is stocked in text.
*/
void ECB_mode(unsigned char** text, int nblock, unsigned char* key, int key_size) {
    unsigned char* expkey = ExpandKey(key,key_size); //get the expanded key
    int nround = get_nround(key_size);
    int i;
    for(i = 0; i< nblock; i++) {
        cipher_block(text[i], expkey, nround); // just cipher each block independantly
    }
    free(expkey);
}

/*
@param text the text to cipher
@param nblock the number of block in text
@param key the encryption key
@param key_size the size of the key
This function use the ECB mode to decrypt text. The result is stocked in text.
*/
void inv_ECB_mode(unsigned char** text, int nblock, unsigned char* key, int key_size) {
    unsigned char* expkey = ExpandKey(key,key_size); //same process
    int nround = get_nround(key_size);
    int i;
    for(i = 0; i< nblock; i++) {
        decipher_block(text[i], expkey, nround); //using the decryption aes algorithm
    }
    free(expkey);
}

/*
@param text the text to cipher
@param nblock the number of block in text
@param key the encryption key
@param key_size the size of the key
@param init the intial vector
This function use the CBC mode to encrypt text. The result is stocked in text.
*/

void CBC_mode(unsigned char** text, int nblock, unsigned char* key, int key_size, unsigned char* init) {
    unsigned char* expkey = ExpandKey(key,key_size); 
    int nround = get_nround(key_size);
    int i;
    XOR_blocks(text[0],init, size_block); //Xoring the first block with the initial vector
    cipher_block(text[0], expkey, nround); // ciphering the first block
    for(i = 1; i< nblock; i++) {
        XOR_blocks(text[i], text[i-1], size_block); //each block is xored with the previous ciphered one
        cipher_block(text[i], expkey, nround);
    }
    free(expkey);
}

/*
@param text the text to cipher
@param nblock the number of block in text
@param key the encryption key
@param key_size the size of the key
This function use the CBC mode to decrypt text. The result is stocked in text.
*/

void inv_CBC_mode(unsigned char** text, int nblock, unsigned char* key, int key_size, unsigned char* init) {
    unsigned char* expkey = ExpandKey(key,key_size); //doing the process backwards
    int nround = get_nround(key_size);
    int i;
    int temp;
    for(i = 1; i < nblock; i++) {
        temp = nblock - i;
        decipher_block(text[temp], expkey, nround); //still using the AES decryption algorithm
        XOR_blocks(text[temp], text[temp - 1], size_block);
        
    }
    decipher_block(text[0], expkey, nround);
    XOR_blocks(text[0], init, size_block); //last step is the first step of the encryption process 
    free(expkey);
    
}

/*
@param text the text to cipher
@param nblock the number of block in text
@param tsize the size of the blocks
@param key the encryption key
@param key_size the size of the key
@param init the intial vector
This function use the CBC mode to encrypt text. The result is stocked in text.
*/

void CFB_mode(unsigned char** text, int nblock, int tsize, unsigned char* key, int key_size, unsigned char* init){
    unsigned char* expkey = ExpandKey(key,key_size); 
    int nround = get_nround(key_size);
    int i;
    int j;
    int delt = size_block - tsize; //gap between size of blocks ans size needed for AES
    unsigned char temp[size_block]; // creating copies of init 
    unsigned char I[size_block];
    for(int i = 0; i<size_block; i++) {
        temp[i] = init[i];
        I[i] = init[i];
    }
    for(i = 0; i < nblock; i++){
        cipher_block(temp,expkey,nround); //ciphering temp
        XOR_blocks(text[i], temp, tsize); //xor the first block with the first bits of temp
        for(j = 0; j < delt; j++) {
            I[j] = I[j + tsize]; // shifting the previous init
            temp[j] = I[j]; // stocking it in temp
        }
        for(j = 0; j < tsize; j++) {
            I[delt + j] = text[i][j]; // adding the firsts bit of the previous block
            temp[delt + j] = I[delt + j]; // updating temp
        }
    }
    free(expkey);
}

/*
@param text the text to cipher
@param nblock the number of block in text
@param tsize the size of the blocks
@param key the encryption key
@param key_size the size of the key
@param init the intial vector
This function use the CFB mode to decrypt text. The result is stocked in text.
*/

void inv_CFB_mode(unsigned char** text, int nblock, int tsize, unsigned char* key, int key_size, unsigned char* init){
    unsigned char* expkey = ExpandKey(key,key_size); // same process but backward
    int nround = get_nround(key_size);
    int i;
    int j;
    int delt = size_block - tsize;
    unsigned char temp[size_block];
    unsigned char I[size_block];
    for(i = 0; i < size_block; i++){
        I[i] = init[i];
    }
    
    for(i = 0; i < nblock; i++){
        for(int j = 0; j<size_block; j++) {
            temp[j] = I[j];
        }
        cipher_block(temp,expkey,nround); // decryption AES algorithm is not needed
        for(j = 0; j < delt; j++) {
            I[j] = I[j + tsize];
        }
        for(j = 0; j < tsize; j++) {
            I[delt + j] = text[i][j];
        }
        XOR_blocks(text[i], temp, tsize);
    }
    free(expkey);
}

/*
@param text the text to cipher
@param nblock the number of block in text
@param tsize the size of the blocks
@param key the encryption key
@param key_size the size of the key
@param authtag the authentification tag that will be calculated and stored in this array
@param authdata the authentification data
@param init the intial vector
@param LenA and LenC the 64 bit long representation of the bit length of the authentification data and the ciphered text(respectively).
This function use the GCM mode to encrypt text and calculate the authentification tag. The result are stocked in text and authtag.
*/

void GCM_mode(unsigned char** text, int nblock, unsigned char* key, int key_size, unsigned char* authtag, unsigned char* authdata, unsigned char* IV, long long int lenA, long long int lenC) {

    int i;
    unsigned char* expkey = ExpandKey(key,key_size);
    int nround = get_nround(key_size);

    unsigned long long int H[2];
    unsigned long long int multH[256];
    unsigned char zero[size_block] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    cipher_block(zero,expkey,nround); // calculating H = Ek(0)
    state_to_64int(zero,H); 
    precompute_F128(H,multH); // Precomputing the value to make the multiplication by H faster

    unsigned long long int data[2];  // used for multiplication
    associate(authtag,authdata);
    state_to_64int(authtag,data);
    unsigned long long int tag[2];
    fast_mult_F128(data,tag,multH); // putting the result of the multiplication in tag
    int64_to_state(authtag, tag);

    unsigned char temp1[size_block];
    unsigned char temp2[size_block];

    unsigned char IVcopy[size_block]; // copy of IV
    associate(IVcopy,IV);
    incr(IVcopy); // counter 0 is incr(IV)
    associate(temp1, IVcopy);
    cipher_block(temp1, expkey, nround); // temp 1 will be used for the final xor

    for(i = 0; i < nblock; i++) {

        incr(IVcopy); // coutner += 1
        associate(temp2, IVcopy); // transforming the counter into a state
        cipher_block(temp2,expkey,nround); // encrytion of the counter
        XOR_blocks(text[i], temp2, size_block); // Xor The text with the ciphered counter

        XOR_blocks(authtag, text[i], size_block); // calculation of the authtag
        state_to_64int(authtag, data);
        fast_mult_F128(data, tag, multH); // multiplication
        int64_to_state(authtag, tag); // storing the result in authtag
    }

    unsigned long long int lenAC[2] ={ lenA, lenC };
    int64_to_state(temp2, lenAC); 
    XOR_blocks(authtag, temp2, size_block); // Xor with lenA || lenC
    state_to_64int(authtag,data);
    fast_mult_F128(data,tag,multH); // last multiplication 
    int64_to_state(authtag, tag);
    XOR_blocks(authtag, temp1, size_block); // final XOR

    free(expkey);

}

/*
@param text the text to cipher
@param nblock the number of block in text
@param tsize the size of the blocks
@param key the encryption key
@param key_size the size of the key
@param authtag the authentification tag 
@param authdata the authentification data
@param init the intial vector
@param LenA and LenC the 64 bit long representation of the bit length of the authentification data and the ciphered text(respectively).
This function use the GCM mode to calculate the authtag and compare it with the one gived in parameters. If they are the same, proceed to decipher the text. Else, return an error
*/

void inv_GCM_mode(unsigned char** text, int nblock, unsigned char* key, int key_size, unsigned char* authtag, unsigned char* authdata, unsigned char* IV, long long int lenA, long long int lenC) {
    int i;
    // The beggining is the same process but we don't cipher counters (except the first one) and we only calculate the authentification tag
    unsigned char* expkey = ExpandKey(key,key_size);
    int nround = get_nround(key_size);
    unsigned long long int H[2];
    unsigned long long int multH[256];
    unsigned char zero[size_block] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    cipher_block(zero,expkey,nround);
    state_to_64int(zero,H);
    precompute_F128(H,multH); // creating a fast multiplicatio by H array

    unsigned char authtag2[size_block]; // authtag2 is the authtag we calculate
    unsigned long long int data[2];
    associate(authtag2,authdata);
    state_to_64int(authtag2,data);
    unsigned long long int tag[2];
    fast_mult_F128(data,tag,multH);
    int64_to_state(authtag2, tag);

    unsigned char temp1[size_block];
    unsigned char temp2[size_block];

    unsigned char IVcopy[size_block];
    associate(IVcopy,IV);
    incr(IVcopy);
    associate(temp1, IVcopy);
    cipher_block(temp1, expkey, nround);

    for(i = 0; i < nblock; i++) {

        XOR_blocks(authtag2, text[i], size_block);
        state_to_64int(authtag2, data);
        fast_mult_F128(data, tag, multH);
        int64_to_state(authtag2, tag);

    }
    unsigned long long int lenAC[2] ={ lenA, lenC };
    int64_to_state(temp2, lenAC);
    XOR_blocks(authtag2, temp2, size_block);
    state_to_64int(authtag2,data);
    fast_mult_F128(data,tag,multH);
    int64_to_state(authtag2, tag);
    XOR_blocks(authtag2, temp1, size_block); // final XOR
    for(i = 0; i < size_block; i++) {
        if(authtag[i] != authtag2[i]) { // comparaison with the authtag in parameter
            fprintf(stderr, "ERROR : Univalid authentification for GCM \n");
            free(expkey);
            exit(EXIT_FAILURE);
        }
    }

     for(i = 0; i < nblock; i++) { // ce can now decipher the text

        incr(IVcopy); // counter += 1
        associate(temp2, IVcopy); 
        cipher_block(temp2,expkey,nround); // cipher the counter
        XOR_blocks(text[i], temp2, size_block); // xored with the cipher block to get the decrypted block

    }
    free(expkey);

}