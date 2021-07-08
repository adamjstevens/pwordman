#include "pwm_crypto.h"

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

void SHA256_CALC(char* string, unsigned char* hash) {
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, string, strlen(string));
    SHA256_Final(hash, &sha256);
    hash[SHA256_DIGEST_LENGTH] = 0;
}