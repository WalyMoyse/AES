#include <stdio.h>
#include <stdlib.h>
#include <getopt.h>
#include <err.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "../include/AES.h"
#include "../include/parser.h"
#include "../include/cipher.h"
#include "../include/keyexp.h"
#include "../include/modes.h"
#include "../include/tools.h"
#include <limits.h>

/*
Function that display the help message of -h.
*/

void usage() {
    printf("Usage :\n\n");
    printf("./AES -c -k KEY -m MODE \n");
    printf("./AES -t -m MODE\n\n");
    printf("-h,      --help            : Display this help and exit.\n") ;
    printf("-k KEY,  --key KEY         : Set your private key in hexadecimal. Must be 128, 129 or 256 bits.\n");
    printf("-a AUTH, --authdata AUTH   : Set the authentification data in hexadecimal. Must be 128 bits or less. Only used for GCM mode.\n");
    printf("-g TAG,  --authtag TAG     : Set the authentification tag in hexadecimal. Must be 128 bits. Only used for GCM decryption.\n");
    printf("-v IV,   --init_vector IV  : Set the initial vector in hexadecimal. Must be 128 bits or less. Not used in ECB mode.\n");
    printf("-f NAME, --filename NAME   : Give the name of the file you want to (de)cipher. Not necessary if you want to use alice.txt.\n");
    printf("-m MODE, --mode MODE       : Specify the mode you want to use between ECB, CBC, CFB, GCM.\n");
    printf("-c,      --cipher          : Encrypt your text.\n");
    printf("-d,      --decipher        : Decrypt your text.\n");
    printf("-t,      --test            : Perform a performance test on alice.txt by ciphering the text 100 times. Mode must be specified.\n");
    printf("-i,      --hexa_input      : Use this option if the file you want to (de)cipher is wrote in hexadecimal.\n");
    printf("-o,      --hexa_output     : Use this option if you want your result to be written in hexadecimal.\n");
    printf("-b SIZE, --block_size SIZE : Specify the size of your block for CFB mode in decimal.\n");
}

int main(int argc, char *argv[]) {

    /*
    the parsing of arguments is made inside the main functions
    */
    
    static struct option long_options[] = {

        //  Creation of the struct containing all options
        {"help", no_argument,0,'h'},
        {"key", required_argument,0,'k'},
        {"authdata",required_argument,0,'a'},
        {"authtag", required_argument,0,'g'},
        {"init_vector",required_argument,0,'v'},
        {"filename",required_argument,0,'f'},
        {"mode", required_argument,0,'m'},
        {"cipher", no_argument,0,'c'},
        {"decipher", no_argument,0,'d'},
        {"test", no_argument,0,'t'},
        {"hexa_input", no_argument,0,'i'},
        {"hexa_output", no_argument,0,'o'},
        {"block_size",required_argument,0,'b'}
    };

    // initialization of the private key that contain the default key
    unsigned char key[32] = {   0x00, 0x01, 0x02, 0x03,
                                0x04, 0x05, 0x06, 0x07,
                                0x08, 0x09, 0x0a, 0x0b,
                                0x0c, 0x0d, 0x0e, 0x0f,
                                0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00,
                                0x00, 0x00, 0x00, 0x00};

    // initialization of the auth tag, auth data and the init vect as 128 bits vectors with only 0
    unsigned char authdata[size_block] = {  0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00};                           
    
    unsigned char authtag[size_block] = {   0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00,
                                            0x00, 0x00, 0x00, 0x00,
                                             0x00, 0x00, 0x00, 0x00};

    unsigned char IV[size_block] = {    0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00,
                                        0x00, 0x00, 0x00, 0x00};
    
    char temp[33]; // array that will be used for the conversion of authtag, authdata and IV from string to the hexadecimal vector they contain.
    int opt;
    int cipher = 0; // Track if the user want to cipher or decipher
    bool test = false; // Track if the user want to perform a test
    bool hexa_input = false; // Track if the input file is in hexadecimal
    bool hexa_output = false; // Track if the output file must be in hexadecimal
    int key_size = 0; // Track the size of the key that the user gave
    bool gave_IV = false;  // Track if the user gave an init vect
    bool gave_authdata = false; // Track if the user gave an authdata
    bool gave_authtag = false; // Track if the user gave an authtag
    char *file_name = NULL; // Track the name of the fill
    int nblock; // Track the number of block in the text
    int mode = 0; // track the mode selected
    unsigned long len = 0; // temporary value;
    int tsize = 0; // track the size of blocks for CFB
    long long int lenC; // lenC and lenA are only used for GCM mode
    long long int lenA = 0;
    
    struct timespec start, end; // Struct used for tests
    double elapsed_time;
    int i; // only used for "for" loop
    while( (opt = getopt_long(argc, argv, "hk:a:g:v:f:m:cdtiob:", long_options,NULL))!= -1 ) { // argument parsing
        switch(opt){
            case 'h' :
                usage();
                exit(EXIT_SUCCESS);

            case 'k' :
                if(key_size != 0) { 
                    errx(EXIT_FAILURE, "2 keys were given but only one is expected. \n");
                }
                if (strncmp(optarg, "0x", 2) == 0) { // removing the 0x of the hexadecimal format if present
                    optarg += 2;
                }
                len = strlen(optarg); // length of the key
                if(len == 32) {
                    key_size = size_block; // key_size is the size of the key in octet 
                }
                else if(len == 48) {
                    key_size = 24;
                }
                else if(len == 64) {
                    key_size = 32;
                }
                else {
                    errx(EXIT_FAILURE, "Unsupported size key. You key has a length  of %lu bits but must be 128, 129 or 256.\n", len*4);
                }
                convert_str_hexa(optarg, key, key_size); // we update key to contain the argument of option -k
                break;

            case 'a' :
                if(gave_authdata) {
                    errx(EXIT_FAILURE, "2 authentification data were given. Expected one or none. \n");
                }
                if (strncmp(optarg, "0x", 2) == 0) { // same as -k
                    optarg += 2;
                }
                len = strlen(optarg);
                if(len > 32) {
                    errx(EXIT_FAILURE, "Authentification data is too long. Size given : %lu bits but maximum size is 128. \n", len*4);
                }
                zero_array(temp); // we update temp to be equal to {'0','0",....,'0'}
                strcpy(temp,optarg); // temp is equal to the argument padded with 0
                temp[len] = 48; // patch of an issue
                convert_str_hexa(temp, authdata, size_block); // We update authdata with the argument padded with 0.
                gave_authdata = true;
                lenA = len*4; // lenA is expressed in bits
                break;
                
            case 'g' : // same process as 'a' option
                if(gave_authtag) {
                    errx(EXIT_FAILURE, "2 authentification tag were given. Expected one or none. \n");
                }
                if (strncmp(optarg, "0x", 2) == 0) {
                    optarg += 2;
                }
                len = strlen(optarg);
                if(len != 32) {
                    errx(EXIT_FAILURE, "Authentification tag must be 128 bits long.\n");
                }
                zero_array(temp);
                strcpy(temp,optarg);
                temp[len] = 48;
                convert_str_hexa(temp, authtag, size_block);
                gave_authtag = true;
                break;

            case 'v' : // same process as 'a' and 'g' option
                if(gave_IV) {
                    errx(EXIT_FAILURE, "2 initialisation vector were given. Expected one or none. \n");
                }
                if (strncmp(optarg, "0x", 2) == 0) {
                    optarg += 2;
                }
                
                len = strlen(optarg);
                
                if(len > 32) {
                    errx(EXIT_FAILURE, "Initialisation vector is too long. Size given : %lu bits but maximum size is 128. \n", len*4);
                }
                zero_array(temp);
                strcpy(temp,optarg);
                temp[len] = 48;
                convert_str_hexa(temp, IV, size_block);
                gave_IV = true;
                break;

            case 'f' :
                if(file_name) {
                    errx(EXIT_FAILURE, "2 file names were given. Expected one ore none. \n");
                }
                file_name = optarg; // update of filename
                break;

            case 'm' :
                if(mode) {
                    errx(EXIT_FAILURE, "2 modes were given. Expected one. \n");
                }
                if(strcmp(optarg, "ECB") == 0) {
                    mode = 1; // mode = 1 for ECB
                }
                else if(strcmp(optarg, "CBC") == 0) {
                    mode = 2; // 2 for CBC
                }
                else if(strcmp(optarg, "CFB") == 0) {
                    mode = 3; // 3 for CFB
                }
                else if(strcmp(optarg, "GCM") == 0) {
                    mode = 4; // 4 for GCM
                }
                else {
                    errx(EXIT_FAILURE, "Unvalid mode option given. option must be ECB, CBC, CFB or GCM \n");
                }
                break;

            case 'c' :
                if(cipher == 2) {
                    errx(EXIT_FAILURE, " Options 'c' and 'd' can't be used in the same command line. \n");
                }
                else {
                    cipher = 1; // cipher = 1 mean we are ciphering
                }
                break;

            case 'd' :
                if(cipher == 1) {
                    errx(EXIT_FAILURE, " Options 'c' and 'd' can't be used in the same command line. \n");
                }
                else {
                    cipher = 2; // cipher = 2 for deciphering
                }
                break;

            case 't' : // 't' 'i' and 'o' are just a boolean update
                test = true; 
                break;

            case 'i' :
                hexa_input = true;
                break;

            case 'o' :
                hexa_output = true;
                break;

            case 'b' : 
                if(tsize) {
                    errx(EXIT_FAILURE, "2 blocks size were given. Expected one or none. \n");
                }
                len = strlen(optarg);
                convert_str_deci(optarg, &tsize, len);
                if(!tsize) {
                    errx(EXIT_FAILURE, "Block size can't be 0.\n");
                }
                else if(tsize > 128) {
                    errx(EXIT_FAILURE, "Block size can't exceed 128 bits. \n");
                }
                else if(tsize % 8 != 0) { // I did not implemented block size with portions of octet (I don't know if it is used)
                    errx(EXIT_FAILURE, "This version of CFB mode only accept multiples of 8 as block size. \n");
                }
                tsize /= 8; // tsize is expressed in octet
                break;

            default :
                errx(EXIT_FAILURE, "Invalid option(s). Use -h or --help for help. \n");
        }
    }
    // cheking if the command was valid
    if(!mode) { // I Did not put a mode as the default mode
        errx(EXIT_FAILURE, "No mode was given. Please choose a mode using -m with arguments ECB, CBC, CFB or GCM \n");
    }
    if(!cipher && !test) {
        errx(EXIT_FAILURE, "None of the -c -d -t options were used. \n");
    }
    if(test && cipher == 2) {
        errx(EXIT_FAILURE, "decipher test is not implemented. \n");
    }

    if(!key_size) {
        key_size = size_block;
        printf("No key was given. Default key used : 0x000102030405060708090A0B0C0D0E0F\n");
    }
    if(!file_name && !test) {
        file_name = "alice.txt";
        printf("No file in parameter. Default file used : alice.txt\n");
    }
    if(file_name && test) {
        file_name = "alice.txt";
        printf("The test will only be made on alice.txt -f is not necesseary with -t\n");
    }
    if(!file_name && test) {
        file_name = "alice.txt";
    }
   // if any argument is useless, the programm will continue but will warn the user
   // if an argument is missing, the programme will used default value and warn the user (except for the auth tag when using GCM in decipher mode)
    if(mode == 1) {
        if(gave_authdata) {
            printf("Authentification data was given but will not be used for ECB mode\n");
        }
        if(gave_authtag) {
            printf("Authentification tag was given but will not be used for ECB mode\n");
        }
        if(gave_IV) {
            printf("Initialisation vector was given but will not be used for ECB mode\n");
        }
    }

    else if(mode == 2) {
        if(gave_authdata) {
            printf("Authentification data was given but will not be used for CBC mode\n");
        }
        if(gave_authtag) {
            printf("Authentification tag was given but will not be used for CBC mode\n");
        }
        if(!gave_IV) {
            printf("No initialisation vector was given for CBC mode. Default init vect used : 0x00000000000000000000000000000000\n");
        }
    }

    else if(mode == 3) {
        if(gave_authdata) {
            printf("Authentification data was given but will not be used for CFB mode\n");
        }
        if(gave_authtag) {
            printf("Authentification tag was given but will not be used for CFB mode\n");
        }
        if(!gave_IV) {
            printf("No initialisation vector was given for CFB mode. Default init vect used : 0x00000000000000000000000000000000\n");
        }
        if(!tsize) {
            printf("No block size was given for CFB mode. Default size : 128\n");
        }
    }

    else if(mode == 4) {
        if(!(gave_authdata) && (cipher == 1 || test)) {
            printf("No authentification data was given for GCM mode. Default auth data used : 0x00000000000000000000000000000000\n");
        }
        if(!(gave_authdata) && cipher == 2) {
            printf("No authentification data was given for GCM mode. Trying to decpher with default auth data : 0x00000000000000000000000000000000\n");
        }
        if(gave_authtag && (cipher == 1 || test)) {
            printf("Authentification tag was given but will not be used for CFB mode when ciphering \n");
        }
        if(!gave_authtag && cipher == 2) {
            errx(EXIT_FAILURE, "Authentification tag is required for GCM mode when deciphering \n");
        }
        if(!gave_IV && (cipher == 1 || test)) {
            printf("No initialisation vector was given for GCM mode. Default init vect used : 0x00000000000000000000000000000000\n");
        }
        if(!gave_IV && cipher == 2) {
            printf("No authentification data was given for GCM mode. Trying to decpher with default init vect : 0x00000000000000000000000000000000\n");
        }
    }

    
    if(tsize && mode != 3) {
        printf("%d",tsize);
        tsize = size_block;
        printf("size block only editable with CFB mode.\n");
    }
    if(!tsize) { // default block size is 16 octets
        tsize = size_block;
    }
    // starting the process
    unsigned char** text; // of the text as a block list
    if(hexa_input) { // reading the file and updating text, nblock (and lenC)
        text = file_parser_hexa(file_name, &nblock, tsize, &lenC);
     }
    else {
        text = file_parser(file_name, &nblock, tsize, &lenC);
    }

    if(mode == 1) { // ECB mode
        if(test) { // test performing
            clock_gettime(CLOCK_REALTIME, &start); 
            for(i = 0; i < 100; i++) {
                ECB_mode(text,nblock,key,key_size);
            }
            clock_gettime(CLOCK_REALTIME, &end);
            elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
            printf("Elapsed time for ECB mode : %f seconds\n", elapsed_time);
            exit(EXIT_SUCCESS);
        }
        else if(cipher == 1) { // ciphering 
            ECB_mode(text,nblock,key,key_size);
        }
        else { // deciphering
            inv_ECB_mode(text,nblock,key,key_size);
        }
    }
    else if(mode == 2) { // CBC
        if(test) { // same process as ECB
            clock_gettime(CLOCK_REALTIME, &start);
            for(i = 0; i < 100; i++) {
                CBC_mode(text,nblock,key,key_size,IV);
            }
            clock_gettime(CLOCK_REALTIME, &end);
            elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
            printf("Elapsed time for CBC mode : %f seconds\n", elapsed_time);
            exit(EXIT_SUCCESS);
        }
        else if(cipher == 1) {
            CBC_mode(text,nblock,key,key_size,IV);
        }
        else {
            inv_CBC_mode(text,nblock,key,key_size,IV);
        }
    }
    else if(mode == 3) { // CFB
        if(test) { // same process
            clock_gettime(CLOCK_REALTIME, &start);
            for(i = 0; i < 100; i++) {
                CFB_mode(text,nblock,tsize,key,key_size,IV);
            }
            clock_gettime(CLOCK_REALTIME, &end);
            elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
            printf("Elapsed time for CFB mode : %f seconds\n", elapsed_time);
            exit(EXIT_SUCCESS);
        }
        else if(cipher == 1) {
            CFB_mode(text,nblock,tsize,key,key_size,IV);
        }
        else {
            inv_CFB_mode(text, nblock, tsize, key, key_size, IV);
        }
    }
    else if(mode == 4) { // GCM mode
        if(test) {
            clock_gettime(CLOCK_REALTIME, &start);
            for(i = 0; i < 100; i++) {
                GCM_mode(text,nblock,key,key_size,authtag,authdata,IV,lenA,lenC);
            }
            clock_gettime(CLOCK_REALTIME, &end);
            elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
            printf("Elapsed time for GCM mode : %f seconds\n", elapsed_time);
            exit(EXIT_SUCCESS);
        }
        else if(cipher == 1) {
            GCM_mode(text,nblock,key,key_size,authtag,authdata,IV,lenA,lenC);
            printf("Your authentification tag is : 0x"); // Giving the user his authentification tag when ciphering a text.
            for(i = 0; i < size_block; i++) {
                printf("%02X", authtag[i]);
            }
            printf("\n");
        }
        else {
            inv_GCM_mode(text,nblock,key,key_size,authtag,authdata,IV,lenA,lenC);
        }
    }
    char *output_file_name; // name of the output file
    if(cipher == 1) {
        output_file_name = "ciphered_text.txt"; // the user can not choose the name
    }
    else {
        output_file_name = "deciphered_text.txt";
    }
    create_file(text,nblock,output_file_name,hexa_output,tsize); // creating the file and wrinting the result
    free_text(text,nblock); 
    exit(EXIT_SUCCESS);
    }
