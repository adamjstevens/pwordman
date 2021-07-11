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

unsigned char random_byte(void) {
    char buffer[1];

    while (1) {
        int rc = RAND_bytes(buffer, 1);
        if (rc != 1) continue;
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

unsigned char* generate_bytes(int n) {
    char* output = malloc(n + 1);
    memset(output, 0, sizeof(output));

    int i = 0;
    for (i = 0; i < n; i++) {
        output[i] = random_byte();
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

void generate_salted_password_hash(char* password, 
        unsigned char* salt, unsigned char* buffer) {

    unsigned char saltedPassword[500];

    int i;
    for (i = 0; i < SALT_LEN; i++) {
        saltedPassword[i] = salt[i];
    }
    saltedPassword[i] = 0;

    // strcat((char*) saltedPassword, (char*) salt);
    strcat((char*) saltedPassword, (char*) password);
    unsigned char saltedPasswordHash[SHA256_DIGEST_LENGTH + 1];
    SHA256_CALC((char*) saltedPassword, saltedPasswordHash);
    strcpy((char*) buffer, (char*) saltedPasswordHash);
    // printf("%s\n", saltedPasswordHash);
}

int encrypt(char* plaintext, unsigned char* key,
        unsigned char* iv, unsigned char* ciphertext) {
    EVP_CIPHER_CTX* ctx;
    int plaintext_len = strlen(plaintext);
    int len;
    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Encryption failure.\n");
        exit(1);
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Encryption failure.\n");
        exit(1);
    }

    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, 
            plaintext_len)) {
        fprintf(stderr, "Encryption failure.\n");
        exit(1);
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fprintf(stderr, "Encryption failure.\n");
        exit(1);
    }
    ciphertext_len += len; 

    EVP_CIPHER_CTX_free(ctx);
    // printf("%d\n", ciphertext_len);
    return ciphertext_len;
}

int decrypt(unsigned char* ciphertext, int ciphertext_len, unsigned char* key, 
        unsigned char* iv, char* plaintext) {
    EVP_CIPHER_CTX* ctx;
    int len;   
    int plaintext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fprintf(stderr, "Encryption failure.\n");
        exit(1);
    }

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
        fprintf(stderr, "Encryption failure.\n");
        exit(1);
    }

    if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, 
            ciphertext_len)) {
        fprintf(stderr, "Encryption failure.\n");
        exit(1);
    }

    if (1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        fprintf(stderr, "Encryption failure.\n");
        exit(1);
    }
    plaintext_len += len; 

    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

void encrypt_to_file(char* plaintext, unsigned char* key, 
        unsigned char* iv, FILE* outfile) {
    int requiredLength = 16 * ((int) ceil((double) strlen(plaintext) / 16));
    unsigned char* ciphertext = malloc(requiredLength + 2);
    int ciphertext_len = encrypt(plaintext, key, iv, ciphertext);
    char* plaintext_out = malloc(sizeof(plaintext));
    fwrite(ciphertext, 1, ciphertext_len, outfile);
    fflush(outfile);
    free(ciphertext);
}

cipherfile* read_cipherfile(FILE* file) {
    cipherfile* output = malloc(sizeof(cipherfile));

    int len = 0;
    int c;

    int lastupdate = 0;
    int numupdates = 0;
    int buflen = 1000;

    output->body = malloc(buflen);

    while ((c = fgetc(file)) != EOF) {
        output->body[len++] = (unsigned char) c;

        if (len - lastupdate >= 1000) {
            output->body = realloc(output->body, buflen * numupdates++);
        }
    }
    output->len = len;

    return output;
}

char* decrypt_cipherfile(cipherfile* cfile, unsigned char* key, 
        unsigned char* iv) {
    char* output = malloc(cfile->len);
    decrypt(cfile->body, cfile->len, key, iv, output);
    return output;
}