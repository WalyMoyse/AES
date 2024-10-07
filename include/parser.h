#ifndef PARSER_H
#define PARSER_H
#include <stdio.h>

unsigned char** file_parser(char* filename, int* nblock, int tsize,long long int* lenC);
unsigned char** file_parser_hexa(char* filename, int* nblock, int tsize,long long int* lenC);
void free_text(unsigned char** text, int nblock);
void create_file(unsigned char** text, int nblock,char* filename, bool hexa, int tsize);

#endif /* PARSER_H */