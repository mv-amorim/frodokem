#include "aes/esp_aes.h"

void aes128_init(esp_aes_context *ctx, unsigned char *key);

void aes128_ecb_enc(esp_aes_context *ctx, unsigned char *plaintext, uint16_t plaintext_len, unsigned char *ciphertext);