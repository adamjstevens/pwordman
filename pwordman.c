#include "pwordman.h"

int main(int argc, char** argv) {
    printf("PWORDMAN\n");

    CONFIG* config;
    if (access(".pwm/config", F_OK) == 0) {
        config = read_config();
    } else {
        config = generate_config();
    }

    char* password = input("Enter your password");
    unsigned char key[SHA256_DIGEST_LENGTH + 1];
    SHA256_CALC(password, key);

    //printf("key: %s\niv: %s\n", key, config->iv);

    if (argc == 1) {
        printf("Use ./pwordman help\n");
    } else if (strcmp(argv[1], "generate") == 0 || 
            strcmp(argv[1], "gen") == 0) {
        handle_generate_command(argc, argv);
    } else if (strcmp(argv[1], "read") == 0) {
        read_file();
    } else if (strcmp(argv[1], "get") == 0 || argc == 3) {
        get_pword(argv);
    }

    return 0;
}

void handle_generate_command(int argc, char** argv) {
    if (argc != 4) return;
    FILE* file = fopen(PWORD_FILE, "a");
    char* username = argv[2];
    char* domain = argv[3];
    char* pass = generate_password(PASSWORD_LENGTH);
    fprintf(file, "%s %s %s\n", username, domain, pass);
    printf("Added password for %s\n%s\n", domain, pass);
    fclose(file);
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

char* get_pword(char** argv) {
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
    FILE* configFile = fopen(CONFIG_FILENAME, "r");
    fscanf(configFile, "iv %s", output->iv);
    fclose(configFile);

    //printf("READ COMPLETE\n");

    return output;
}

CONFIG* generate_config(void) {
    //printf("GENERATING CONFIG FILE...\n");

    FILE* configFile = fopen(CONFIG_FILENAME, "w");
    CONFIG* output = malloc(sizeof(CONFIG));
    output->iv = malloc(IV_LEN + 1);
    char* iv = malloc(IV_LEN + 1);

    iv = generate_password(((int) IV_LEN / 8));
    fprintf(configFile, "iv %s\n", iv);
    output->iv = iv;

    fclose(configFile);
    
    return output;
}