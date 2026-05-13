#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <unistd.h>

int main() {
    OpenSSL_add_all_algorithms();

    // Load key
    FILE* f = fopen("/tmp/victim_rsa.key", "r");
    if (!f) { perror("fopen"); return 1; }
    RSA* rsa = PEM_read_RSAPrivateKey(f, NULL, NULL, NULL);
    fclose(f);
    if (!rsa) { ERR_print_errors_fp(stderr); return 1; }

    unsigned char msg[256] = {0x42};
    unsigned char sig[256];
    unsigned int siglen;

    printf("Victim PID: %d\n", getpid());
    fflush(stdout);

    // Loop forever doing RSA private key operations
    while (1) {
        RSA_sign(NID_sha256, msg, 32, sig, &siglen, rsa);
    }

    RSA_free(rsa);
    return 0;
}
