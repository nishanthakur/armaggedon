#define _GNU_SOURCE
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>

int main() {
    OpenSSL_add_all_algorithms();

    /* Generate RSA key */
    FILE* f = fopen("/opt/armageddon/pp_attack/victim_rsa.key", "r");
    if (!f) {
        printf("Generating RSA-2048 key...\n");
        system("openssl genrsa -out /opt/armageddon/pp_attack/victim_rsa.key 2048 2>/dev/null");
        f = fopen("/opt/armageddon/pp_attack/victim_rsa.key", "r");
    }
    if (!f) { perror("fopen"); return 1; }

    EVP_PKEY* pkey = PEM_read_PrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!pkey) { ERR_print_errors_fp(stderr); return 1; }

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) { ERR_print_errors_fp(stderr); return 1; }

    /* Disable blinding — makes cache pattern visible */
    RSA_blinding_off(rsa);

    unsigned char msg[32];
    memset(msg, 0x42, sizeof(msg));
    unsigned char sig[256];
    unsigned int  siglen;

    printf("Victim PID: %d\n", getpid());
    printf("Blinding: OFF\n");
    printf("Running RSA-2048 sign loop...\n");
    fflush(stdout);

    while (1) {
        RSA_sign(NID_sha256, msg, sizeof(msg), sig, &siglen, rsa);
    }

    RSA_free(rsa);
    EVP_PKEY_free(pkey);
    return 0;
}
