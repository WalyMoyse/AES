#include <stdio.h>
#include <stdlib.h>
#include <err.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include "../include/tools.h"

/*
@param c : an unsigned char
@return true if the charater is corresponding to a valid hexadecimal digit, otherwhise, false
*/

bool valid_hexa_char(unsigned char c) {
    if(c >= 65 && c <= 70) { // c is a letter between A and F
        return true;
    }
    if(c >= 97 && c <= 102) { // c is a letter between a and f 
        return true;
    }
    if(c >= 48 && c <= 57) { // c is the representation of digits between 0 and 9
        return true;
    }
    return false; // c is not valid
}

/*
This function convert a string representing an hexadecimal value into an unsigned char array containing the corresponding value
@param input  : the string
@param key : the array where we will store the values
@param key_size : the size of the array key
when this function will be used, input will always have an even number of char and be twice the size of key.
*/
void convert_str_hexa(char* input, unsigned char* key, int key_size) {
    char bytes[2];
    unsigned char c1;
    unsigned char c2;
    for(int i = 0; i < key_size; i++) {
        c1 = (unsigned char) input[2*i]; // regrouping chars in groups of 2 to make an octet
        c2 = (unsigned char) input[2*i + 1];
        if(!(valid_hexa_char(c1) && (valid_hexa_char(c2)))) { // checking chars
            errx(EXIT_FAILURE, "tried to convert unvalid char to hexa\n");
        }
        bytes[0] = (char) c1;
        bytes[1] = (char) c2;
        key[i] = (unsigned char) strtol(bytes, NULL, size_block); // converting the octet into its corresponding value
    }
}

/*
This function convert a string representing a decimal int and give the corresponding value to an int
@param input : the string
@param tsize : the pointer of an int that will track the result
@param len : the size of input
*/
void convert_str_deci(char* input, int* tsize, unsigned long len) {
    unsigned char c;
    for(unsigned long i = 0; i < len; i++) {
        c = (unsigned char) input[i];
        if(!(c >= 48 && c <= 57)) { // checking if the char represent a digit
            errx(EXIT_FAILURE, "Invalid block size option. Option must be given in base 10.\n");
        }
    }
    *tsize = (int) strtol(input, NULL, 10); // converting input
}

/*
This function just take a char array of size 33 and fill its 32 first elements with the char '0'
*/
void zero_array(char input[33]) {
    for(int i = 0; i < 32; i++) {
        input[i] = 48; // code of '0'
    }
}