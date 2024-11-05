#include "aes.h"

void aes128_init(esp_aes_context *ctx, unsigned char *key) {
    esp_aes_init(ctx);
    esp_aes_setkey(ctx, key, 128);
}

void aes128_ecb_enc(esp_aes_context *ctx, unsigned char *plaintext, uint16_t plaintext_len, unsigned char *ciphertext) {
    unsigned int i;
    for(i = 0; i < plaintext_len; i += 16) {
        esp_aes_crypt_ecb(ctx, ESP_AES_ENCRYPT, &plaintext[i], &ciphertext[i]);
    }
}