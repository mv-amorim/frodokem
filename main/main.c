#include <stdio.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "esp_timer.h"
#include "frodokem.h"

#define KEM_TEST_ITERATIONS 101

#define EV_0 (1<<0)
EventGroupHandle_t evgp;

float kg_time[KEM_TEST_ITERATIONS];
float enc_time[KEM_TEST_ITERATIONS];
float dec_time[KEM_TEST_ITERATIONS];
float total_time[KEM_TEST_ITERATIONS];
uint8_t i = 0, step = 1;
int64_t s = 0;

uint8_t pk[CRYPTO_PUBLICKEYBYTES];
uint8_t sk[CRYPTO_SECRETKEYBYTES];
uint8_t ss_encap[CRYPTO_BYTES];
uint8_t ss_decap[CRYPTO_BYTES];
uint8_t ct[CRYPTO_CIPHERTEXTBYTES];

void task_main();
void task_keypair();
void task_encrypt();
void task_decrypt();

void app_main(void)
{
    evgp = xEventGroupCreate();
    xTaskCreate(task_main, "Task main", 2048, NULL, 1, NULL);
}

int compare(const void *a, const void *b) {
    float dif = (*(float *)a - *(float *)b);
    if (dif > 0) return 1;
    if (dif < 0) return -1;
    return 0;
}

float median(float *vec, int tam) {
    qsort(vec, tam, sizeof(float), compare);
    if (tam % 2 != 0)
        return (float)vec[tam / 2];
    else
        return (float)(vec[(tam - 1) / 2] + vec[tam / 2]) / 2.0;
}

void task_main() {
    while(1) {
        switch(step) {
            case 1:
                if(i == 0) {
                    printf("Crypto bytes: %d\n", CRYPTO_BYTES);
                    printf("Testing correctness of key encapsulation mechanism (KEM), tests for %d iterations\n", KEM_TEST_ITERATIONS);
                }
                printf("i = %d\n", i);
                xTaskCreate(task_keypair, "Task key pair", 70000, NULL, 2, NULL);
                xEventGroupWaitBits(evgp, EV_0, pdTRUE, pdTRUE, portMAX_DELAY);
                printf("Keygen: concluído\n");
                break;
            case 2:
                xTaskCreate(task_encrypt, "Task encrypt", 109800, NULL, 2, NULL);
                xEventGroupWaitBits(evgp, EV_0, pdTRUE, pdTRUE, portMAX_DELAY);
                printf("Encap: concluído\n");
                break;
            case 3:
                xTaskCreate(task_decrypt, "Task decrypt", heap_caps_get_largest_free_block(MALLOC_CAP_8BIT), NULL, tskIDLE_PRIORITY, NULL);
                xEventGroupWaitBits(evgp, EV_0, pdTRUE, pdTRUE, portMAX_DELAY);
                printf("Decap: concluído\n");
                break;
            default:
                step = 0;
                if (memcmp(ss_encap, ss_decap, CRYPTO_BYTES) == 0) {
                    total_time[i] = kg_time[i] + enc_time[i] + dec_time[i];
                    i++;
                    if(i == KEM_TEST_ITERATIONS) {
                        printf("%d tests PASSED. All session keys matched.\n", i);
                        printf("Keygen: %.3fs\n", median(kg_time, KEM_TEST_ITERATIONS));
                        printf("Encrypt: %.3f\n", median(enc_time, KEM_TEST_ITERATIONS));
                        printf("Decrypt: %.3fs\n", median(dec_time, KEM_TEST_ITERATIONS));
                        printf("Total: %.3fs\n", median(total_time, KEM_TEST_ITERATIONS));
                        i = 0;
                    }
                } else {
                   printf("ERROR!\n");
                   i = 0;
                }
        }
        step++;
    }
}

void task_keypair() {
    while(1) {
        s = esp_timer_get_time();
        crypto_kem_keypair(pk, sk);
        kg_time[i] = (esp_timer_get_time() - s)/1000000.0;

        xEventGroupSetBits(evgp, EV_0);
        vTaskDelete(NULL);
    }
}

void task_encrypt() {
    while(1) {
        s = esp_timer_get_time();
        crypto_kem_enc(ct, ss_encap, pk);
        enc_time[i] = (esp_timer_get_time() - s)/1000000.0;

        xEventGroupSetBits(evgp, EV_0);
        vTaskDelete(NULL);
    }
}

void task_decrypt() {
    while(1) {
        s = esp_timer_get_time();
        crypto_kem_dec(ss_decap, ct, sk);
        dec_time[i] = (esp_timer_get_time() - s)/1000000.0;

        xEventGroupSetBits(evgp, EV_0);
        vTaskDelete(NULL);
    }
}