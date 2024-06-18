#include "include.h"
#include "struct.h"

unsigned char* hex_to_bin(const char* hex, int out_len) {
    size_t len = strlen(hex);
    if (len % 2 != 0) {
        return NULL;
    }

    out_len = len / 2;
    unsigned char* bin = (unsigned char*) malloc(out_len);
    if (!bin) {
        return NULL;
    }

    for (size_t i = 0; i < out_len; i++) {
        sscanf(hex + 2 * i, "%2hhx", &bin[i]);
    }

    return bin;
}

void parse_certificate(const unsigned char* cert_data, size_t cert_len) {
    extern signing_data* sd;
    const unsigned char* p = cert_data;
    X509* cert = d2i_X509(NULL, &p, cert_len);
    if (!cert) {
        fprintf(stderr, "Failed to parse certificate\n");
        return;
    }

    EVP_PKEY* pkey = X509_get_pubkey(cert);
    if (!pkey) {
        fprintf(stderr, "Failed to get public key\n");
        X509_free(cert);
        return;
    }

    RSA* rsa = EVP_PKEY_get1_RSA(pkey);
    if (!rsa) {
        fprintf(stderr, "Public key is not RSA\n");
        EVP_PKEY_free(pkey);
        X509_free(cert);
        return;
    }

    // 모듈러스와 퍼블릭 익스포넌트 추출
    const BIGNUM* modulus = RSA_get0_n(rsa);
    const BIGNUM* public_exponent = RSA_get0_e(rsa);

    // 모듈러스 출력
    char* modulus_hex = BN_bn2hex(modulus);
    sd->modulus = (const char*)modulus_hex;

    // 퍼블릭 익스포넌트 출력
    char* public_exponent_hex = BN_bn2hex(public_exponent);
    sd->publicexponent = (const char*)public_exponent_hex;

}
