#ifndef PWORDMAN
#define PWORDMAN

#define PASSWORD_LENGTH 23
#define PWORD_FILE "./.pwm/list.pw"

typedef struct {
    char domain[50];
    char password[PASSWORD_LENGTH];
} pword;

typedef struct {
    pword* p;
    int n;
} passwords;

/*
Generates a random character (ASCII-readable)
returns: Random char
*/
char random_char(void);

/*
Generates a random password 
params:
    n: Length of the password 
returns: Secure, random password of length n
*/
char* generate_password(int n);

/*
Handles a generate command from the usr
params: Command line arguments 
*/
void handle_generate_command(int argc, char** argv);

/*
Gets the password for a given domain
params:
    domain: Domain of the password
returns: Password of said domain
*/
char* get_pword(char* domain);

/*
Reads the file from the passwords
returns: Array of pword types
*/
passwords* read_file(void);

#endif