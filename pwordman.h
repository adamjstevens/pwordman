#ifndef PWORDMAN
#define PWORDMAN

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
#include "pwm_crypto.h"
#include "constants.h"

typedef struct {
    char username[INPUT_LIMIT];
    char domain[INPUT_LIMIT];
    char password[PASSWORD_LENGTH];
} pword;

typedef struct {
    pword* p;
    int n;
} passwords;

typedef struct {
    char* iv; 
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
char* get_pword(char** argv);

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
Generates an initial config file (generates iv, etc)
returns: CONFIG struct pointer
*/
CONFIG* generate_config(void);

#endif