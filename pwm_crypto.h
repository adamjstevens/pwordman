#ifndef PWM_CRYPTO
#define PWM_CRYPTO

// STANDARD LIBRARIES
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>

// CRYPTO LIBRARIES
#include <openssl/rand.h>
#include <openssl/sha.h>

// HEADER FILES 
#include "constants.h"

/*
Generates a random character (ASCII-readable)
returns: Random char
*/
char random_char(void);

/*
*/
char random_byte(void);

/*
Generates a random password 
params:
    n: Length of the password 
returns: Secure, random password of length n
*/
char* generate_password(int n);

/*
*/
unsigned char* generate_bytes(int n);

/*
Encrypts the file using AES256-CBC
params:
    plainfile: Filename of the plaintext
    ivfile: Filename of the file with the initialisation vector
*/
void encrypt_file(char* plainfile, char* ivfile);

/*
Generates a SHA256 hash (in string format)
params:
    string: String to generate hash from 
    hash: Buffer to write output to
*/
void SHA256_CALC(char* string, unsigned char* hash);

#endif