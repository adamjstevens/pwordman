#include "pwordman.h"

int main(int argc, char** argv) {
    // Handling .pwm directory creation
    opendir(DIRECTORY);
    if (ENOENT == errno) {
        system("mkdir .pwm");
    }
    // Handling CONFIG file
    CONFIG* config;
    if (access(".pwm/config", F_OK) == 0) { // Directory exists
        config = read_config();
        if (config == NULL) {
            return -1;
        }
    } else { // Directory does not exist
        config = initialise();
    }
    // Password
    char* password = malloc(INPUT_LIMIT + 1);
    hidden_input("Enter your master password: ", password);
    if (!password_matches(config, password)) {
        printf("Incorrect master password\n");
        exit(1);
    }
    unsigned char key[SHA256_DIGEST_LENGTH + 1];
    generate_salted_password_hash(password, config->salt2, key);
    passwords* pwords = read_file(key, config->iv);
    // Commands
    if (argc > 1 && (strcmp(argv[1], "generate") == 0 || 
            strcmp(argv[1], "gen") == 0)) {
        handle_generate_command(pwords, argc, argv);
    } else if (argc == 4 && strcmp(argv[1], "get") == 0) {
        get_entry(argv, pwords);
    } else if (argc == 4 && strcmp(argv[1], "set") == 0) {
        set_password(pwords, argc, argv);
    } else {
        printf("Use ./pwordman help\n");
    }
    // Cleaning up
    FILE* outfile = fopen(ENC_FILE, "w");
    char* str_pwords = pwords_to_str(pwords);
    encrypt_to_file(str_pwords, key, config->iv, outfile);
    fclose(outfile);
    free(pwords);
    free(config);

    return 0;
}

void set_password(passwords* pwords, int argc, char** argv) {
    char* username = argv[2];
    char* domain = argv[3];
    char* msg = malloc(300);
    sprintf(msg, "Enter password for %s @ %s: ", username, domain);
    char* pass = malloc(INPUT_LIMIT);
    hidden_input(msg, pass);
    free(msg);

    if (has_password(pwords, domain, username)) {
        replace_password(pwords, username, domain, pass);
        return;
    }

    add_password(pwords, username, domain, pass);
    show_password(pass, username, domain);
    free(pass);
}

void handle_generate_command(passwords* pwords, int argc, char** argv) {
    if (argc != 5) return;
    char* username = argv[2];
    char* domain = argv[3];
    int password_len = atoi(argv[4]);

    if (has_password(pwords, domain, username)) {
        char* inp = input("Entry already exists. Would you like to generate a new password (y/n)? ");
        if (strcmp(inp, "y\n") == 0 || strcmp(inp, "Y\n") == 0) {
            replace_password(pwords, username, domain,
                    generate_password(password_len));
        }
        return;
    }
    
    char* pass = generate_password(password_len);
    add_password(pwords, username, domain, pass);
    show_password(pass, username, domain);
}

void add_password(passwords* pwords, char* username, char* domain, 
        char* pass) {
    pword* p = malloc(sizeof(pword));
    p->domain = malloc(strlen(domain) + 1);
    p->username = malloc(strlen(username) + 1);
    p->password = malloc(strlen(pass) + 1);
    strcpy(p->domain, domain);
    strcpy(p->password, pass);
    strcpy(p->username, username);

    pwords->p[pwords->n++] = *p;
}

void hidden_input(char* prompt, char* buf) { 
    static struct termios oldt, newt;
    int i = 0;
    printf("%s", prompt);
    FILE* stream = fopen("/dev/tty", "r");
    tcgetattr(fileno(stream), &oldt);
    newt = oldt;
    newt.c_lflag &= ~(ECHO);
    tcsetattr(fileno(stream), TCSANOW, &newt);
    int c;
    while ((c = fgetc(stream)) != '\n' && c != EOF && i < INPUT_LIMIT) {
        buf[i++] = c;
    }
    buf[i] = '\0';
    printf("\n");
    tcsetattr(fileno(stream), TCSANOW, &oldt);
}

void init_iv(CONFIG* config, FILE* configFile) {
    unsigned char* iv = malloc(IV_LEN + 1);
    iv = (unsigned char*) generate_bytes(((int) IV_LEN));
    iv[IV_LEN] = 0;
    fprintf(configFile, "iv %s\n", iv);
    config->iv = iv;
}

void replace_password(passwords* pwords, char* username, char* domain, 
        char* newPassword) {
    for (int i = 0; i < pwords->n; i++) {
        if (strcmp(username, pwords->p[i].username) == 0 &&
                strcmp(domain, pwords->p[i].domain) == 0) {
            pwords->p[i].password = newPassword;
        }
    }
    show_password(newPassword, username, domain);
}

void show_password(char* password, char* username, char* domain) {
    char* msg = malloc(300);
    sprintf(msg, "Press [ENTER] once complete\n\
\nPassword for %s at domain %s:\n",
            username, domain);
    printf(msg);
    printf("%s  ", password);
    input("");
    printf("\033[2A]\r");
    for (int i = 0; i < 2; i++) {
        for (int j = 0; j < strlen(msg); j++) {
            printf(" ");
        }
        printf("\n");
    }
    printf("\n");
}

void read_config_trait(FILE* infile, char* trait, int n, unsigned char* buf) {
    // Trait name + " "
    for (int i = 0; i <= strlen(trait); i++) {
        int c = fgetc(infile);
        if (c == EOF) {
            return;
        }
    }
    // Value
    for (int i = 0; i < n; i++) {
        buf[i] = fgetc(infile);
        if (buf[i] == EOF) {
            return;
        }
    }
    // Newline
    int c = fgetc(infile);
    if (c == EOF) {
        return;
    }
}

char* pwords_to_str(passwords* pwords) {
    char* output = malloc(pwords->n * 3 * INPUT_LIMIT);
    output[0] = 0;
    for (int i = 0; i < pwords->n; i++) {
        char* line = malloc(INPUT_LIMIT * 3);
        sprintf(line, "%s %s %s\n", 
                pwords->p[i].username, 
                pwords->p[i].domain, 
                pwords->p[i].password);
        strcat(output, line);
    }
    return output;
}

char* get_entry(char** argv, passwords* ps) {
    char* username = argv[2];
    char* domain = argv[3];
    for (int i = 0; i < ps->n; i++) {
        if (strcmp(ps->p[i].domain, domain) == 0 &&
                strcmp(ps->p[i].username, username) == 0) {
            show_password(ps->p[i].password, username, domain);
            return ps->p[i].password;
        }
    }

    return NULL;
}

char* input(char* prompt) {
    printf("%s", prompt);
    char* inp = malloc(INPUT_LIMIT);
    fgets(inp, INPUT_LIMIT, stdin);
    return inp;
}

char* get_password_from_user(void) {
    char* password = malloc(INPUT_LIMIT);
    printf(SEPERATOR);
    printf("Looks like this is your first time using pwordman, please set a master password below.\n");
    while (true) {
        password = malloc(INPUT_LIMIT + 1);
        hidden_input("Set your master password: ", password);
        char* confirmPassword = malloc(INPUT_LIMIT + 1); 
        hidden_input("Confirm your master password: ", confirmPassword);
        if (strcmp(password, confirmPassword) == 0) {
            break;
        }
    }
    printf(SEPERATOR);
    return password;
}

unsigned char* init_salt(CONFIG* config, FILE* configFile, char* label) {
    unsigned char* salt = malloc(SALT_LEN + 1);
    salt = (unsigned char*) generate_bytes(SALT_LEN);
    salt[SALT_LEN] = 0;
    fprintf(configFile, "%s %s\n", label, salt);
    return salt;
}

passwords* read_file(unsigned char* key, unsigned char* iv) {
    pword* pwords = malloc(sizeof(pword) * 500);   
    FILE* cfile = fopen(ENC_FILE, "r");

    if (cfile == NULL) {
        passwords* output = malloc(sizeof(passwords));
        output->p = pwords;
        output->n = 0;
        return output;
    }

    cipherfile* cf = read_cipherfile(cfile);
    fclose(cfile);
    char* plaintext = decrypt_cipherfile(cf, key, iv);
    int i = 0;
    size_t len = 200;
    char* line = malloc(len);
    const char delim[2] = "\n";
    char *savePlain;
    line = strtok_r(plaintext, delim, &savePlain);
    while (line != NULL) {
        if (strlen(line) < 5 || is_str_empty(line)) break;
        char* username = malloc(INPUT_LIMIT);
        char* domain = malloc(INPUT_LIMIT);
        char* password = malloc(PASSWORD_LENGTH);
        char* saveLine;
        username = strtok_r(line, " ", &saveLine);
        domain = strtok_r(NULL, " ", &saveLine);
        password = strtok_r(NULL, " ", &saveLine);

        pword* p = malloc(sizeof(pword));
        p->username = malloc(INPUT_LIMIT);
        p->domain = malloc(INPUT_LIMIT);
        p->password = malloc(INPUT_LIMIT);

        strcpy(p->username, username);
        strcpy(p->domain, domain);
        strcpy(p->password, password);
        pwords[i] = *p;
        i++;
        line = strtok_r(NULL, delim, &savePlain);
    }

    passwords* output = malloc(sizeof(passwords));
    output->p = pwords;
    output->n = i;
    return output;
}

CONFIG* read_config(void) {
    CONFIG* output = malloc(sizeof(CONFIG));
    FILE* configFile = fopen(CONFIG_FILENAME, "r");
    // Allocating memory 
    output->iv = malloc(IV_LEN);
    output->salt1 = malloc(SALT_LEN);
    output->salt2 = malloc(SALT_LEN);
    output->saltedPwordHash = malloc(SHA256_DIGEST_LENGTH);
    // Reading traits
    read_config_trait(configFile, "iv", IV_LEN, output->iv);
    read_config_trait(configFile, "salt1", SALT_LEN, output->salt1);
    read_config_trait(configFile, "salt2", SALT_LEN, output->salt2);
    read_config_trait(configFile, "salted_pword", SHA256_DIGEST_LENGTH, 
        output->saltedPwordHash);
    if (output->saltedPwordHash == NULL) printf("NULL\n");
    fclose(configFile);

    return output;
}

CONFIG* initialise(void) {
    FILE* configFile = fopen(CONFIG_FILENAME, "w");
    CONFIG* output = malloc(sizeof(CONFIG));
    output->iv = malloc(IV_LEN + 1);
    // Initialise IV
    init_iv(output, configFile);
    // Initialise salt
    output->salt1 = init_salt(output, configFile, "salt1");
    output->salt2 = init_salt(output, configFile, "salt2");
    // Initialise password 
    char* password = get_password_from_user();
    // Generate salted password
    unsigned char* saltedPasswordHash = malloc(SHA256_DIGEST_LENGTH + 1);
    generate_salted_password_hash(password, output->salt1, saltedPasswordHash);
    fprintf(configFile, "salted_pword ");
    fwrite(saltedPasswordHash, 1, SHA256_DIGEST_LENGTH, configFile);
    fprintf(configFile, "\n");
    output->saltedPwordHash = saltedPasswordHash;
    fclose(configFile);

    return output;
}

bool is_str_empty(char* str) {
    int i = 0; 
    while(str[i] != '\0') {
        if (!(str[i] < 32 || str[i] > 126)) {
            return false;
        }
        i++;
    }
    return true;;
}

bool has_password(passwords* pwords, char* domain, char* username) {
    for (int i = 0; i < pwords->n; i++) {
        if ((strcmp(pwords->p[i].username, username) == 0) && 
                strcmp(pwords->p[i].domain, domain) == 0) {
            return true;
        }
    }
    return false;
}

bool password_matches(CONFIG* config, char* password) {
    unsigned char* saltedPasswordHash = malloc(SHA256_DIGEST_LENGTH + 1);
    generate_salted_password_hash(password, config->salt1, saltedPasswordHash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) { 
        if (saltedPasswordHash[i] != config->saltedPwordHash[i]) {
            return false;
        }
    }
    return true;
}