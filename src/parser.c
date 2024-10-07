#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <stdbool.h>
#include <unistd.h>
#include "../include/parser.h"
#include "../include/tools.h"

/*
This function read a file and return the text as an array of char block

@param filename : the name of the file that contains the file
@param nblock : a pointer that will track the number of block needed
@param tsize : the size of the block in octet
@param lenC a pointer that will track the size of the ciphered text in bits
@return a 2D array containing the text in the fill. Each block contains tsize unsigned char
*/

unsigned char** file_parser(char* filename, int* nblock, int tsize,long long int* lenC) {
    FILE *file;
    file = fopen(filename, "r"); // reading the file
    unsigned char** text; // the result
    int i;
    int j;
    
    if (file == NULL) {
        fprintf(stderr, "ERROR : failed to open %s\n", filename);
        exit(EXIT_FAILURE);
    }
    fseek(file,0,SEEK_END); //going at the end of the file
    *lenC = ftell(file); //getting the number of char in the file
    fseek(file,0,SEEK_SET); //returning at the beggining
    *nblock = (*lenC + tsize - 1) / tsize; //update of nblock
    text =(unsigned char**)malloc( *nblock * sizeof(unsigned char*)); // memory allocation
    if(text == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    for(i = 0; i < *nblock; i++) {
        text[i] = (unsigned char*)malloc((tsize + 1)* sizeof(unsigned char)); // memory allocation for each block
        if(text[i] == NULL) {
            fprintf(stderr, "Failed to allocate memory\n");
            fclose(file);
            free(text);
            exit(EXIT_FAILURE);
        }
    }

    unsigned char c;
    for(i = 0; i < *nblock - 1; i++) {
        for(j = 0; j < tsize; j++) {
            c = fgetc(file); // next char of the file
            text[i][j] = c; // updating the result 
        }
        text[i][tsize] = '\0';
    }
    int padd = *lenC % tsize; // padding needed for the last block
    if(padd == 0){
        padd = tsize;
    }
    for (i = 0; i < padd; i++) {
        c = fgetc(file);
        text[*nblock - 1][i] = c; // last char of the file
    } 
    for(i = padd; i<tsize; i++){
        c = fgetc(file);
        text[*nblock - 1][i] = 0; // padding
    }
    *lenC = *nblock * 128; // lenC is in bits
    fclose(file);
    return text;
}

/*
This function read a file written in hexadecimal and return the text as an array of char block. 

@param filename : the name of the file that contains the file
@param nblock : a pointer that will track the number of block needed
@param tsize : the size of the block in octet
@param lenC a pointer that will track the size of the ciphered text in bits
@return a 2D array containing the text in the fill. Each block contains tsize unsigned char
*/


unsigned char** file_parser_hexa(char* filename, int* nblock, int tsize,long long int* lenC) {
    FILE *file;
    file = fopen(filename, "r"); // reading the file
    unsigned char** text;
    int i;
    int j;
    char c;
    *lenC = 0;
    if (file == NULL) {
        fprintf(stderr, "ERROR : failed to open %s\n", filename);
        exit(EXIT_FAILURE);
    }
    
    while((c = fgetc(file)) != EOF) { // we must verify and count the number of significant char in the file
        if(c != ' ' && c != '\n' && c != '\t') { // space, tabulation and line skip are ignored
            if(valid_hexa_char(c)) { // verifying the char
                *lenC += 1;
            }
            else {
                errx(EXIT_FAILURE, "Unvalid character for hexadecimal in file %s. \n", filename);
            }
        }
    }

    *lenC *= 4; // size in bits
    *nblock = (*lenC + tsize * 8 - 1) / (tsize * 8); // updating number of blocks
    text =(unsigned char**)malloc( *nblock * sizeof(unsigned char*)); // memory allocation
    if(text == NULL) {
        fprintf(stderr, "Failed to allocate memory\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    for(i = 0; i < *nblock; i++) {
        text[i] = (unsigned char*)malloc((tsize + 1)* sizeof(unsigned char));
        if(text[i] == NULL) {
            fprintf(stderr, "Failed to allocate memory\n");
            fclose(file);
            free(text);
            exit(EXIT_FAILURE);
        }
    }

    fseek(file,0,SEEK_SET);
    i = 0;
    j = 0;
    bool even = false;
    char bytes[2]; // used to convert 2 hexadecimal number into a char
    while((c = fgetc(file)) != EOF){
        if(c != ' ' && c != '\n' && c != '\t') {
            if(even) {
                even = !even;
                bytes[1] = (unsigned char)c;
                text[i][j] = (unsigned char) strtol(bytes, NULL, size_block); // converting "bytes" into its hexadecimal value
                if(j == tsize - 1) {
                    text[i][tsize] = '\0';
                    j = 0;
                    i += 1;
                }
                else {
                    j += 1;
                }
            }
            else {
                even = !even;
                bytes[0] = (unsigned char)c;
            }
        }
    }
    if(even) { // in case we had an odd number of significant char
        bytes[1] = 0;
        text[i][j] = (unsigned char)strtol(bytes, NULL, size_block);
        if(j == tsize - 1) {
            text[i][tsize] = '\0';
            j = 0;
            i += 1;
        }
        else {
            j += 1;
        }
    }

    while(j != 0) { // padding
        text[i][j] = 0;
        if(j == tsize - 1){
            j = 0;
            text[i][tsize] = '\0';
        }
        else {
            j += 1;
        }
    }
    *lenC = *nblock * 128; // updating lenC
    fclose(file);
    return text;
}

/*
This function is used to free the 2D array and all its array

@param text the 2D array
@param nblock the number of block in text
*/

void free_text(unsigned char** text, int nblock){
    int i;
    for (i = 0; i < nblock; i++) {
        free(text[i]); // free each block
    }
    free(text); // free the text
}

/*
This function create a file and write the text inside of it
@param text : the 2D array
@param nblock : the number of block in text
@param filename : the name of the new file
@param hexa : a boolean that says if we need to write in he file in hexa or not
@param tsize : the size of txtx's blocks
*/

void create_file(unsigned char** text, int nblock,char* filename, bool hexa,int tsize) {
    FILE *overwrite = fopen(filename, "r"); // trying to read the file
    int i;
    int j;
    if(overwrite != NULL) { // if we are able to do so, it means we are trying to write on an already existing file. 
        printf("file already exist. Unvalid name\n");
        fclose(overwrite);
        free_text(text,nblock);
        exit(EXIT_FAILURE);
    }
    
    FILE *new_file = fopen(filename,"w"); // wrintting mode
    if(new_file == NULL) {
        printf("failed to create the file %s\n", filename);
        fclose(overwrite);
        free_text(text,nblock);
        exit(EXIT_FAILURE);
    }

    if(hexa) { // wrinting in hexa
        for(i = 0; i < nblock; i++) {
            for(j = 0; j < tsize; j++) {
                fprintf(new_file, "%02X ",text[i][j]); // each line will represent a block
            }
            fprintf(new_file, "\n");
        } 
    }
    else { // writting in ASCII
        for(i = 0; i < nblock; i++) {
            for(j = 0; j < tsize; j++) {
                fprintf(new_file, "%c",text[i][j]);
            }
        } 
    }
    fclose(new_file);
    printf("The file %s has been created\n", filename);
}