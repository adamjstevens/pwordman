#ifndef PWM_CRYPTO
#define PWM_CRYPTO

/* CRYPTO LIBRARIES */
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>

// HEADER FILES 
#include "constants.h"

/*
Keeps track of the body of the file and the length
*/
typedef struct {
    unsigned char* body;
    int len;
} cipherfile;

/*
Encrypts plaintext to file 
params:
    plaintext: C-string to encrypt to the file 
    key: Key used in encryption 
    iv: Initialisation vector to use in encryption
    outfile: File to write ciphertext to
*/
void encrypt_to_file(char* plaintext, unsigned char* key, 
        unsigned char* iv, FILE* outfile);

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

/*
Encrypts the plaintext using AES256-CBC
params:
    plaintext: Plaintext to encrypt 
    key: Key to use in encryption 
    iv: Initialisation vector to use in encryption 
    ciphertext: Buffer to write to
returns: length of the ciphertext
*/
int encrypt(char* plaintext, unsigned char* key,
        unsigned char* iv, unsigned char* ciphertext);


/*
Decrypts the ciphertext using AES256-CBC
params:
    ciphertext: Ciphertext to decrypt 
    ciphertext_len: Length of the ciphertext
    key: Key to use in decryption 
    iv: Initialisation vector to use in decryption 
    plaintext: Buffer to write to
returns: length of the plaintext
*/
int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, 
        unsigned char* iv, char* plaintext);

/*
Generates a random character (ASCII-readable)
returns: Random char
*/
char random_char(void);

/*
returns: Random byte
*/
unsigned char random_byte(void);

/*
Generates a random password 
params:
    n: Length of the password 
returns: Secure, random password of length n
*/
char* generate_password(int n);

/*
Decrypts the cipherfile 
params: 
    cfile: cipherfile struct to decrypt 
    key: Key to use in the decryption 
    iv: Initialisation vector to use in decryption
returns: Decrypted body (plaintext)
*/
char* decrypt_cipherfile(cipherfile* cfile, unsigned char* key, 
        unsigned char* iv);

/*
Generates random bytes using random_byte()
params:
    n: Number of bytes to generate 
returns: Array of random bytes
*/
unsigned char* generate_bytes(int n);

/*
Reads the cipherfile 
params:
    file: File to read from 
returns: cipherfile struct
*/
cipherfile* read_cipherfile(FILE* file);

#endif