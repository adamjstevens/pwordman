// STANDARD LIBRARIES
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

// CRYPTO LIBRARIES
#include <openssl/rand.h>

// HEADER FILES
#include "pwordman.h"

int main(int argc, char** argv) {
    if (argc == 1) {
        printf("Use ./pwordman help\n");
    } else if (strcmp(argv[1], "generate") == 0 || 
            strcmp(argv[1], "gen") == 0) {
        handle_generate_command(argc, argv);
    } else if (strcmp(argv[1], "read") == 0) {
        read_file();
    } else if (strcmp(argv[1], "get") == 0 || argc == 3) {
        get_pword(argv[2]);
    }
    return 0;
}

char random_char(void) {
    char buffer[1];

    while (1) {
        int rc = RAND_bytes(buffer, 1);
        if (rc != 1) continue;
        if (buffer[0] < 33 || buffer[0] > 126) continue;
        break;
    }

    return buffer[0];
}

char* generate_password(int n) {
    char* output = malloc(n + 1);
    memset(output, 0, sizeof(output));

    int i = 0;
    for (i = 0; i < n; i++) {
        output[i] = random_char();
    }
    output[i] = '\0';

    return output;
}

void handle_generate_command(int argc, char** argv) {
    if (argc != 3) return;
    // FILE* file = fopen(PWORD_FILE, "a");
    char* domain = argv[2];
    char* pass = generate_password(PASSWORD_LENGTH);
    // fprintf(file, "%s %s\n", domain, pass);
    printf("Added password for %s\n%s\n", domain, pass);
    // fclose(file);
}

passwords* read_file(void) {
    pword* pwords = malloc(sizeof(pword) * 50);
    FILE* file = fopen(PWORD_FILE, "r");
    
    int i = 0;
    size_t len = 80;
    char* line = malloc(len);
    ssize_t read;
    while ((read = getline(&line, &len, file)) != -1) {
        char* domain = malloc(50);
        char* password = malloc(PASSWORD_LENGTH);
        domain = strtok(line, " ");
        password = strtok(NULL, " ");

        pword* p = malloc(sizeof(pword));
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

char* get_pword(char* domain) {
    passwords* ps = read_file();

    for (int i = 0; i < ps->n; i++) {
        if (strcmp(ps->p[i].domain, domain) == 0) {
            printf("%s\n", ps->p[i].password);
            return ps->p[i].password;
        }
    }

    return NULL;
}
