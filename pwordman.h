#ifndef PWORDMAN
#define PWORDMAN

// STANDARD LIBRARIES
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>
#include <termios.h>

// CRYPTO LIBRARIES
#include <openssl/rand.h>
#include <openssl/sha.h>

// HEADER FILES
#include "pwm_crypto.h"
#include "constants.h"

typedef struct {
    char username[INPUT_LIMIT];
    char domain[INPUT_LIMIT];
    char password[INPUT_LIMIT];
} pword;

typedef struct {
    pword* p;
    int n;
} passwords;

typedef struct {
    unsigned char* iv; 
    unsigned char* salt; 
    unsigned char* saltedPwordHash;
} CONFIG;

/*
Handles a generate command from the usr
params: Command line arguments 
*/
void handle_generate_command(int argc, char** argv);

/*
Gets the password for a given domain
params:
    argv: arguments of the program
returns: Password of said domain
*/
char* get_entry(char** argv);

/*
Reads the file from the passwords
returns: Array of pword types
*/
passwords* read_file(void);

/*
Gets a line of input through the command line 
params:
    prompt: Prompt for the user 
returns: text input from the user
*/
char* input(char* prompt);

/*
Reads the config file using CONFIG_FILENAME
returns: CONFIG struct pointer
*/
CONFIG* read_config(void);

/*
*/
unsigned char* read_config_trait(FILE* infile, char* trait, int n);

/*
Generates an initial config file (generates iv, etc)
returns: CONFIG struct pointer
*/
CONFIG* initialise(void);

/*
*/
void init_iv(CONFIG* config, FILE* configFile);

/*
*/
void init_salt(CONFIG* config, FILE* configFile);

/*
*/
char* get_password_from_user(void);

/*
*/
void generate_salted_password(char* password, unsigned char* salt);

/*
*/
bool has_password(char* domain, char* username);

/*
*/
void generate_salted_password_hash(char* password, 
        unsigned char* salt, unsigned char* buffer);

/*
*/
bool password_matches(CONFIG* config, char* password);

void hidden_input(char* prompt, char *buf);

#endif