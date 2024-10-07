#ifndef TOOLS_H
#define TOOLS_H
#include <stdio.h>

#define size_block 16

bool valid_hexa_char(unsigned char c);
void convert_str_hexa(char* input, unsigned char* key, int key_size);
void convert_str_deci(char* input, int* tsize, unsigned long len);
void zero_array(char input[33]);
#endif /* TOOLS_H */