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
        exit(1);
    }

    unsigned char key[SHA256_DIGEST_LENGTH + 1];
    SHA256_CALC(password, key);

    // printf("key: %s\niv: %s\n", key, config->iv);

    if (argc == 1) {
        printf("Use ./pwordman help\n");
    } else if (strcmp(argv[1], "generate") == 0 || 
            strcmp(argv[1], "gen") == 0) {
        handle_generate_command(argc, argv);
    } else if (strcmp(argv[1], "read") == 0) {
        read_file();
    } else if (strcmp(argv[1], "get") == 0 || argc == 3) {
        get_entry(argv);
    }

    return 0;
}

void handle_generate_command(int argc, char** argv) {
    if (argc != 5) return;
    FILE* file = fopen(PWORD_FILE, "a");
    char* username = argv[2];
    char* domain = argv[3];

    if (has_password(domain, username)) {
        printf("Entry already exists for username & domain\n");
        return;
    }

    int password_len = atoi(argv[4]);
    char* pass = generate_password(password_len);
    fprintf(file, "%s %s %s\n", username, domain, pass);
    printf("Added password for %s\n%s\n", domain, pass);
    fclose(file);
}

bool has_password(char* domain, char* username) {
    passwords* pwords = read_file();
    for (int i = 0; i < pwords->n; i++) {
        if ((strcmp(pwords->p[i].username, username) == 0) && 
                strcmp(pwords->p[i].domain, domain) == 0) {
            return true;
        }
    }
    free(pwords);
    return false;
}

passwords* read_file(void) {
    pword* pwords = malloc(sizeof(pword) * 50);
    FILE* file = fopen(PWORD_FILE, "r");
    
    int i = 0;
    size_t len = 80;
    char* line = malloc(len);
    ssize_t read;
    while ((read = getline(&line, &len, file)) != -1) {
        char* username = malloc(INPUT_LIMIT);
        char* domain = malloc(INPUT_LIMIT);
        char* password = malloc(PASSWORD_LENGTH);
        username = strtok(line, " ");
        domain = strtok(NULL, " ");
        password = strtok(NULL, " ");

        pword* p = malloc(sizeof(pword));
        strcpy(p->username, username);
        strcpy(p->domain, domain);
        strcpy(p->password, password);
        // printf("%s %s\n", p->domain, p->password);
        pwords[i] = *p;
        i++;
    }
    fclose(file);

    passwords* output = malloc(sizeof(passwords));
    output->p = pwords;
    output->n = i;

    return output;
}

char* get_entry(char** argv) {
    passwords* ps = read_file();

    char* username = argv[2];
    char* domain = argv[3];

    for (int i = 0; i < ps->n; i++) {
        if (strcmp(ps->p[i].domain, domain) == 0 &&
                strcmp(ps->p[i].username, username) == 0) {
            printf("%s\n", ps->p[i].password);
            return ps->p[i].password;
        }
    }

    return NULL;
}

char* input(char* prompt) {
    printf("%s: ", prompt);
    char* inp = malloc(INPUT_LIMIT);
    fgets(inp, INPUT_LIMIT, stdin);
    return inp;
}

CONFIG* read_config(void) {
    //printf("READING CONFIG FILE\n");
    CONFIG* output = malloc(sizeof(CONFIG));
    output->iv = malloc(IV_LEN + 1);
    output->salt = malloc(SALT_LEN + 1);
    output->saltedPwordHash = malloc(SHA256_DIGEST_LENGTH + 1);

    FILE* configFile = fopen(CONFIG_FILENAME, "r");

    // Reading traits
    output->iv = read_config_trait(configFile, "iv", IV_LEN);
    output->salt = read_config_trait(configFile, "salt", SALT_LEN);
    output->saltedPwordHash = read_config_trait(configFile, "salted_pword",
        SHA256_DIGEST_LENGTH);

    fclose(configFile);

    // printf("iv %s\nsalt %s\nsalted_pword %s\n", output->iv, 
    //         output->salt, output->saltedPwordHash);

    return output;
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

CONFIG* initialise(void) {
    FILE* configFile = fopen(CONFIG_FILENAME, "w");
    CONFIG* output = malloc(sizeof(CONFIG));
    output->iv = malloc(IV_LEN + 1);
    output->salt = malloc(SALT_LEN + 1);
    output->saltedPwordHash = malloc(SHA256_DIGEST_LENGTH + 1);
    // Initialise IV
    init_iv(output, configFile);
    // Initialise salt
    init_salt(output, configFile);
    // Initialise password 
    char* password = get_password_from_user();
    // Generate salted password
    unsigned char saltedPasswordHash[SHA256_DIGEST_LENGTH + 1];
    generate_salted_password_hash(password, output->salt, saltedPasswordHash);
    fprintf(configFile, "salted_pword %s\n", saltedPasswordHash);
    output->saltedPwordHash = saltedPasswordHash;

    fclose(configFile);
    
    return output;
}

void init_iv(CONFIG* config, FILE* configFile) {
    // Initialise IV
    unsigned char* iv = malloc(IV_LEN + 1);
    iv = (unsigned char*) generate_bytes(((int) IV_LEN));
    iv[IV_LEN] = 0;
    fprintf(configFile, "iv %s\n", iv);
    config->iv = iv;
}

void init_salt(CONFIG* config, FILE* configFile) {
    unsigned char* salt = malloc(SALT_LEN + 1);
    salt = (unsigned char*) generate_bytes(((int) SALT_LEN));
    salt[SALT_LEN] = 0;
    fprintf(configFile, "salt %s\n", salt);
    config->salt = salt;
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

void generate_salted_password_hash(char* password, 
        unsigned char* salt, unsigned char* buffer) {

    unsigned char saltedPassword[500];
    saltedPassword[0] = 0;
    strcat((char*) saltedPassword, (char*) salt);
    strcat((char*) saltedPassword, (char*) password);
    unsigned char saltedPasswordHash[SHA256_DIGEST_LENGTH + 1];
    SHA256_CALC((char*) saltedPassword, saltedPasswordHash);
    strcpy((char*) buffer, (char*) saltedPasswordHash);
    // printf("%s\n", saltedPasswordHash);
}

bool password_matches(CONFIG* config, char* password) {
    unsigned char saltedPasswordHash[SHA256_DIGEST_LENGTH + 1];
    generate_salted_password_hash(password, config->salt, saltedPasswordHash);
    // printf("%s\n", saltedPasswordHash);
    // printf("%s\n", config->saltedPwordHash);

    if (strcmp((char*) saltedPasswordHash,
            (char*) config->saltedPwordHash) == 0) {
        return true;
    }
    return false;
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