#include "pwordman.h"

int main(int argc, char** argv) {
    // Handling .pwm directory creation
    opendir(DIRECTORY);
    if (ENOENT == errno) {
        system("mkdir .pwm");
    }
    // Handling CONFIG file
    CONFIG* config;
    if (access(".pwm/config", F_OK) == 0) {
        config = read_config();
        if (config == NULL) {
            return -1;
        }
    } else {
        config = initialise();
    }
    // Password
    char* password = malloc(INPUT_LIMIT + 1);
    hidden_input("Enter your password: ", password);
    if (!password_matches(config, password)) {
        printf("Incorrect password\n");
        exit(1);
    }

    unsigned char key[SHA256_DIGEST_LENGTH + 1];
    generate_salted_password_hash(password, config->salt2, key);
    passwords* pwords = read_file(key, config->iv);
    if (argc > 1 && (strcmp(argv[1], "generate") == 0 || 
            strcmp(argv[1], "gen") == 0)) {
        handle_generate_command(pwords, argc, argv);
    } else if (argc == 4 && strcmp(argv[1], "get") == 0) {
        // printf("yo\n");
        get_entry(argv, pwords);
    } else {
        printf("Use ./pwordman help\n");
    }
    
    FILE* outfile = fopen(ENC_FILE, "w");
    char* str_pwords = pwords_to_str(pwords);
    encrypt_to_file(str_pwords, key, config->iv, outfile);
    fclose(outfile);
    free(pwords);
    free(config);

    return 0;
}

void handle_generate_command(passwords* pwords, int argc, char** argv) {
    if (argc != 5) return;
    char* username = argv[2];
    char* domain = argv[3];
    int password_len = atoi(argv[4]);

    if (has_password(pwords, domain, username)) {
        char* inp = input("Entry already exists. Would you like to generate a new password (y/n)? ");
        if (strcmp(inp, "y") == 0) {
            replace_password(pwords, username, domain,
                    generate_password(password_len));
        }
        return;
    }
    
    char* pass = generate_password(password_len);
    pword* p = malloc(sizeof(pword));
    p->domain = malloc(strlen(domain) + 1);
    p->username = malloc(strlen(username) + 1);
    p->password = malloc(strlen(pass) + 1);

    strcpy(p->domain, domain);
    strcpy(p->password, pass);
    strcpy(p->username, username);

    pwords->p[pwords->n++] = *p;
    printf("Password:\n%s\n", pass);
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
    printf("Password:\n%s\n", newPassword);
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
        // printf("Line: %s", line);
        strcat(output, line);
    }
    // printf("%s\n", output);
    return output;
}

char* get_entry(char** argv, passwords* ps) {
    char* username = argv[2];
    char* domain = argv[3];
    for (int i = 0; i < ps->n; i++) {
        if (strcmp(ps->p[i].domain, domain) == 0 &&
                strcmp(ps->p[i].username, username) == 0) {
            printf("Password:\n%s\n", ps->p[i].password);
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
    while (true) {
        password = malloc(INPUT_LIMIT + 1);
        hidden_input("Set your password: ", password);
        char* confirmPassword = malloc(INPUT_LIMIT + 1); 
        hidden_input("Confirm your password: ", confirmPassword);
        if (strcmp(password, confirmPassword) == 0) {
            break;
        }
    }
    return password;
}

unsigned char* read_config_trait(FILE* infile, char* trait, int n) {
    unsigned char* output = malloc(n + 1);
    // Trait + " "
    for (int i = 0; i <= strlen(trait); i++) {
        int c = fgetc(infile);
        if (c == EOF) {
            return NULL;
        }
    }
    // Value
    for (int i = 0; i < n; i++) {
        output[i] = fgetc(infile);
        if (output[i] == EOF) {
            return NULL;
        }
    }
    // Newline
    int c = fgetc(infile);
    if (c == EOF) {
        return NULL;
    }

    output[n] = 0;
    return output;
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
    //printf("READING CONFIG FILE\n");
    CONFIG* output = malloc(sizeof(CONFIG));
    output->iv = malloc(IV_LEN + 1);
    output->salt1 = malloc(SALT_LEN + 1);
    output->salt2 = malloc(SALT_LEN + 1);
    output->saltedPwordHash = malloc(SHA256_DIGEST_LENGTH + 1);
    FILE* configFile = fopen(CONFIG_FILENAME, "r");
    // Reading traits
    output->iv = read_config_trait(configFile, "iv", IV_LEN);
    output->salt1 = read_config_trait(configFile, "salt1", SALT_LEN);
    output->salt2 = read_config_trait(configFile, "salt2", SALT_LEN);
    output->saltedPwordHash = read_config_trait(configFile, "salted_pword",
        SHA256_DIGEST_LENGTH);
    fclose(configFile);

    return output;
}

CONFIG* initialise(void) {
    FILE* configFile = fopen(CONFIG_FILENAME, "w");
    CONFIG* output = malloc(sizeof(CONFIG));
    output->iv = malloc(IV_LEN + 1);
    output->saltedPwordHash = malloc(SHA256_DIGEST_LENGTH + 1);
    // Initialise IV
    init_iv(output, configFile);
    // Initialise salt
    output->salt1 = init_salt(output, configFile, "salt1");
    output->salt2 = init_salt(output, configFile, "salt2");
    // Initialise password 
    char* password = get_password_from_user();
    // Generate salted password
    unsigned char saltedPasswordHash[SHA256_DIGEST_LENGTH + 1];
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
            //printf("char = %d\n", str[i]);
            return false;
        }
        i++;
        //printf("yo\n");
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
    unsigned char saltedPasswordHash[SHA256_DIGEST_LENGTH + 1];
    generate_salted_password_hash(password, config->salt1, saltedPasswordHash);

    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        if (saltedPasswordHash[i] != config->saltedPwordHash[i]) {
            return false;
        }
    }

    return true;
}