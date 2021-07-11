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

// HEADER FILES
#include "pwm_crypto.h"
#include "constants.h"

/*
The pword struct defines a single password
*/
typedef struct {
    char* username;
    char* domain;
    char* password;
} pword;

/*
The passwords struct defines a list of passwords with a count
*/
typedef struct {
    pword* p;
    int n;
} passwords;

/*
The CONFIG struct represents the config attributes
*/
typedef struct {
    unsigned char* iv; 
    unsigned char* salt1; 
    unsigned char* salt2; 
    unsigned char* saltedPwordHash;
} CONFIG;

/*
Handles a generate command from the usr
params:
    pwords: passwords struct
    argc, argv.
*/
void handle_generate_command(passwords* pwords, int argc, char** argv);

/*
Initialises IV value within the config file 
params:
    config: CONFIG struct 
    configFile: File to write to
*/
void init_iv(CONFIG* config, FILE* configFile);

/*
Generates a salted hash value given a string 
params:
    password: String to salt and hash 
    salt: Salt to combine with password 
    buffer: Buffer to write output to 
returns: SHA256(salt || password)

*/
void generate_salted_password_hash(char* password, 
        unsigned char* salt, unsigned char* buffer);

/*
Get hidden input (i.e. password) from user 
params: 
    prompt: The input prompt 
    buf: Buffer to write to 
*/
void hidden_input(char* prompt, char *buf);

/*
Shows the password, with the ability to erase the password
params: 
    password: Password to show
*/
void show_password(char* password);

/*
Replaces a password in the list
params: 
    pwords: passwords struct 
    username: Username to replace 
    domain: Domain to replace 
    newPassword: Password to replace the old one with
*/
void replace_password(passwords* pwords, char* username, char* domain, 
        char* newPassword);

/*
Gets the password for a given domain
params:
    argv: arguments of the program
    ps: passwords struct
returns: Password of said domain
*/
char* get_entry(char** argv, passwords* ps);

/*
Converts a passwords struct to a string 
params:
    pwords: Passwords struct 
returns: char* string representation
*/
char* pwords_to_str(passwords* pwords);

/*
Gets a line of input through the command line 
params:
    prompt: Prompt for the user 
returns: text input from the user
*/
char* input(char* prompt);

/*
returns: New password from user
*/
char* get_password_from_user(void);

/*
Reads a config attribute
params: 
    infile: File to read from 
    trait: String of the trait (e.g. "salt1")
    n: How big the expectec trait is to be (in bytes)
returns: Value of said trait
*/
unsigned char* read_config_trait(FILE* infile, char* trait, int n);

/*
Initialises salt value within the config file 
params: 
    config: CONFIG struct 
    configFile: File to write to
    label: Label of the salt (e.g. salt1)
returns: value of the salt
*/
unsigned char* init_salt(CONFIG* config, FILE* configFile, char* label);

/*
Reads the file from the passwords
params:
    key: Key of the encryption 
    iv: Initialisation vector of the encryption
returns: Array of pword types
*/
passwords* read_file(unsigned char* key, unsigned char* iv);

/*
Reads the config file using CONFIG_FILENAME
returns: CONFIG struct pointer
*/
CONFIG* read_config(void);

/*
Generates an initial config file (generates iv, etc)
returns: CONFIG struct pointer
*/
CONFIG* initialise(void);

/*
Determines if a string is 'empty'
'empty' = no readable characters 
params:
    str: String used in determination 
returns: True if string is empty, else false
*/
bool is_str_empty(char* str);

/*
Determines if a password is correct 
params:     
    config: CONFIG struct pointer to compare against 
    password: Password to compare wiht 
returns: True if password is correct, else false
*/
bool password_matches(CONFIG* config, char* password);

/*
Checks the passwords to see if there is already a password there 
params:
    pwords: passwords struct to compare with
    domain: Domain of the password (website, etc)
    username: Username of the password
returns: True if password entry exists, else false
*/
bool has_password(passwords* pwords, char* domain, char* username);

#endif
