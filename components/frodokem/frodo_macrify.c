#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"

#ifdef USE_AES
#include "aes/aes.h"
#else
#include "sha3/fips202.h"
#endif

#define EV_T0 (1<<0)
#define EV_T1 (1<<1)


typedef struct TaskDataStruct_t
{
    uint16_t id;
    uint16_t *out;
    const uint16_t *s;
    const uint8_t *seed_A;
    const uint16_t *b;
} TaskData_t;

EventGroupHandle_t frodo_macrify_evgp;

#ifndef USE_SINGLECORE
SemaphoreHandle_t out_mutex[PARAMS_NBAR];
#endif

void task_mul_add_as_plus_e(void* param) {
    TaskData_t* data = (TaskData_t*) param;
    uint16_t *out = data->out;

    uint16_t i, j, k;
    i = (PARAMS_N/2) * data->id;
    #ifdef USE_SINGLECORE
    const uint16_t i_max = PARAMS_N;
    #else
    const uint16_t i_max = (PARAMS_N/2) * (1 + data->id);
    #endif
    int16_t a_row[4*PARAMS_N] = {0};

    #ifdef USE_AES
    int16_t a_row_temp[4*PARAMS_N] = {0}; 
    esp_aes_context ctx;
    aes128_init(&ctx, (unsigned char*) data->seed_A);
    for (j = 0; j < PARAMS_N; j += PARAMS_STRIPE_STEP) {
        a_row_temp[j + 1 + 0*PARAMS_N] = j;                     // Loading values in the little-endian order
        a_row_temp[j + 1 + 1*PARAMS_N] = j;
        a_row_temp[j + 1 + 2*PARAMS_N] = j;
        a_row_temp[j + 1 + 3*PARAMS_N] = j;
    }
    #else
    uint8_t seed_A_separated[2 + BYTES_SEED_A];
    uint16_t* seed_A_origin = (uint16_t*)&seed_A_separated;
    memcpy(&seed_A_separated[2], data->seed_A, BYTES_SEED_A);
    #endif

    while(1) {
        #ifdef USE_AES
        for (j = 0; j < PARAMS_N; j += PARAMS_STRIPE_STEP) {    // Go through A, four rows at a time
            a_row_temp[j + 0*PARAMS_N] = i+0;                   // Loading values in the little-endian order                                
            a_row_temp[j + 1*PARAMS_N] = i+1;
            a_row_temp[j + 2*PARAMS_N] = i+2;
            a_row_temp[j + 3*PARAMS_N] = i+3;
        }
        aes128_ecb_enc(&ctx, (uint8_t*)a_row_temp, 4*PARAMS_N*sizeof(int16_t), (uint8_t*)a_row);
        #else
        seed_A_origin[0] = (uint16_t) (i + 0);
        shake128((unsigned char*)(a_row + 0*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
        seed_A_origin[0] = (uint16_t) (i + 1);
        shake128((unsigned char*)(a_row + 1*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
        seed_A_origin[0] = (uint16_t) (i + 2);
        shake128((unsigned char*)(a_row + 2*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
        seed_A_origin[0] = (uint16_t) (i + 3);
        shake128((unsigned char*)(a_row + 3*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
        #endif

        for (k = 0; k < PARAMS_NBAR; k++) {
            uint16_t sum[4] = {0};
            for (j = 0; j < PARAMS_N; j++) {                    // Matrix-vector multiplication            
                uint16_t sp = data->s[k*PARAMS_N + j];
                sum[0] += a_row[0*PARAMS_N + j] * sp;           // Go through four lines with same s
                sum[1] += a_row[1*PARAMS_N + j] * sp;
                sum[2] += a_row[2*PARAMS_N + j] * sp;
                sum[3] += a_row[3*PARAMS_N + j] * sp;
            }
            out[(i+0)*PARAMS_NBAR + k] += sum[0];
            out[(i+2)*PARAMS_NBAR + k] += sum[2];
            out[(i+1)*PARAMS_NBAR + k] += sum[1];
            out[(i+3)*PARAMS_NBAR + k] += sum[3];
        }
        i += 4;

        if(i == i_max) {
            #ifndef USE_SINGLECORE
            if(data->id == 0)
                xEventGroupSetBits(frodo_macrify_evgp, EV_T0);
            else if(data->id == 1)
                xEventGroupSetBits(frodo_macrify_evgp, EV_T1);
            #else
            xEventGroupSetBits(frodo_macrify_evgp, EV_T0);
            #endif

            #ifdef USE_AES
            esp_aes_free(&ctx);
            #endif

            vTaskDelete(NULL);
        }
    }
}

int frodo_mul_add_as_plus_e(uint16_t *out, const uint16_t *s, const uint16_t *e, const uint8_t *seed_A) 
{ // Generate-and-multiply: generate matrix A (N x N) row-wise, multiply by s on the right.
  // Inputs: s, e (N x N_BAR)
  // Output: out = A*s + e (N x N_BAR)
    uint16_t i;

    for (i = 0; i < (PARAMS_N*PARAMS_NBAR); i += 2) {    
        *((uint32_t*)&out[i]) = *((uint32_t*)&e[i]);
    }
    frodo_macrify_evgp = xEventGroupCreate();

    TaskData_t d0 = {0, out, s, seed_A, NULL};
    xTaskCreatePinnedToCore(task_mul_add_as_plus_e, "Task (A*s + e) 0", 40000, (void *) &d0, tskIDLE_PRIORITY, NULL, 0);

    #ifndef USE_SINGLECORE
    TaskData_t d1 = {1, out, s, seed_A, NULL};
    xTaskCreatePinnedToCore(task_mul_add_as_plus_e, "Task (A*s + e) 1", 40000, (void *) &d1, tskIDLE_PRIORITY, NULL, 1);
    EventBits_t bits = xEventGroupWaitBits(frodo_macrify_evgp, EV_T0 | EV_T1, pdTRUE, pdTRUE, portMAX_DELAY);
    if((bits & (EV_T0 | EV_T1)) == (EV_T0 | EV_T1))
        vEventGroupDelete(frodo_macrify_evgp);
    #else
    EventBits_t bits = xEventGroupWaitBits(frodo_macrify_evgp, EV_T0, pdTRUE, pdTRUE, portMAX_DELAY);
    if((bits & EV_T0) == EV_T0)
        vEventGroupDelete(frodo_macrify_evgp);
    #endif

    return 1;
}


void task_mul_add_sa_plus_e(void* param) {
    TaskData_t* data = (TaskData_t*) param;
    uint16_t *out = data->out;

    uint16_t i, j, v;
    v = (PARAMS_N/2) * data->id;
    #ifdef USE_SINGLECORE
    const uint16_t v_max = PARAMS_N;
    #else
    const uint16_t v_max = (PARAMS_N/2) * (1 + data->id);
    #endif

    #ifdef USE_AES
    uint16_t k;
    uint16_t a_cols[PARAMS_N*PARAMS_STRIPE_STEP] = {0};
    uint16_t a_cols_t[PARAMS_N*PARAMS_STRIPE_STEP] = {0};
    uint16_t a_cols_temp[PARAMS_N*PARAMS_STRIPE_STEP] = {0};
    esp_aes_context ctx;
    aes128_init(&ctx, (unsigned char*) data->seed_A);  

    for (i = 0, j = 0; i < PARAMS_N; i++, j += PARAMS_STRIPE_STEP) {
        a_cols_temp[j] = i;                                     // Loading values in the little-endian order
    }
    #else
    uint16_t a_rows[4*PARAMS_N] = {0};
    uint8_t seed_A_separated[2 + BYTES_SEED_A];
    uint16_t* seed_A_origin = (uint16_t*)&seed_A_separated;
    uint16_t sum;
    memcpy(&seed_A_separated[2], data->seed_A, BYTES_SEED_A);
    #endif

    while(1) {
        #ifdef USE_AES
        for (i = 0; i < (PARAMS_N*PARAMS_STRIPE_STEP); i += PARAMS_STRIPE_STEP) {
            a_cols_temp[i + 1] = v;                            // Loading values in the little-endian order
        }
        aes128_ecb_enc(&ctx, (uint8_t*)a_cols_temp, PARAMS_N*PARAMS_STRIPE_STEP*sizeof(int16_t), (uint8_t*)a_cols);
        for (i = 0; i < PARAMS_N; i++) {                        // Transpose a_cols to have access to it in the column-major order.
            for (k = 0; k < PARAMS_STRIPE_STEP; k++) {
                a_cols_t[k*PARAMS_N + i] = a_cols[i*PARAMS_STRIPE_STEP + k];
            }
        }
        for (i = 0; i < PARAMS_NBAR; i++) {
            for (k = 0; k < PARAMS_STRIPE_STEP; k += PARAMS_PARALLEL) {
                uint16_t sum[PARAMS_PARALLEL] = {0};
                for (j = 0; j < PARAMS_N; j++) {                // Matrix-vector multiplication
                    uint16_t sp = data->s[i*PARAMS_N + j];
                    sum[0] += sp * a_cols_t[(k+0)*PARAMS_N + j];
                    sum[1] += sp * a_cols_t[(k+1)*PARAMS_N + j];
                    sum[2] += sp * a_cols_t[(k+2)*PARAMS_N + j];
                    sum[3] += sp * a_cols_t[(k+3)*PARAMS_N + j];
                }
                out[i*PARAMS_N + v + k + 0] += sum[0];
                out[i*PARAMS_N + v + k + 2] += sum[2];
                out[i*PARAMS_N + v + k + 1] += sum[1];
                out[i*PARAMS_N + v + k + 3] += sum[3];
            }
        }
        v += PARAMS_STRIPE_STEP;

        #else
        seed_A_origin[0] = (uint16_t) (v + 0);
        shake128((unsigned char*)(a_rows + 0*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
        seed_A_origin[0] = (uint16_t) (v + 1);
        shake128((unsigned char*)(a_rows + 1*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
        seed_A_origin[0] = (uint16_t) (v + 2);
        shake128((unsigned char*)(a_rows + 2*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);
        seed_A_origin[0] = (uint16_t) (v + 3);
        shake128((unsigned char*)(a_rows + 3*PARAMS_N), (unsigned long long)(2*PARAMS_N), seed_A_separated, 2 + BYTES_SEED_A);

            #ifndef USE_SINGLECORE
            if(data->id == 0) {
                for(i = 0; i < PARAMS_NBAR; i++) {
                    xSemaphoreTake(out_mutex[i], PARAMS_N*7);
                    for(j = 0; j < PARAMS_N; j++) {
                        sum = 0;
                        sum += data->s[i*PARAMS_N + 0+v] * a_rows[0*PARAMS_N + j];
                        sum += data->s[i*PARAMS_N + 1+v] * a_rows[1*PARAMS_N + j];
                        sum += data->s[i*PARAMS_N + 2+v] * a_rows[2*PARAMS_N + j];
                        sum += data->s[i*PARAMS_N + 3+v] * a_rows[3*PARAMS_N + j];
                        out[i*PARAMS_N + j] += sum;
                    }
                    xSemaphoreGive(out_mutex[i]);
                }
            } else if(data->id == 1) {
                for(i = PARAMS_NBAR/2; i < PARAMS_NBAR; i++) {
                    xSemaphoreTake(out_mutex[i], PARAMS_N*7);
                    for(j = 0; j < PARAMS_N; j++) {
                        sum = 0;
                        sum += data->s[i*PARAMS_N + 0+v] * a_rows[0*PARAMS_N + j];
                        sum += data->s[i*PARAMS_N + 1+v] * a_rows[1*PARAMS_N + j];
                        sum += data->s[i*PARAMS_N + 2+v] * a_rows[2*PARAMS_N + j];
                        sum += data->s[i*PARAMS_N + 3+v] * a_rows[3*PARAMS_N + j];
                        out[i*PARAMS_N + j] += sum;
                    }
                    xSemaphoreGive(out_mutex[i]);
                }
                for(i = 0; i < PARAMS_NBAR/2; i++) {
                    xSemaphoreTake(out_mutex[i], PARAMS_N*7);
                    for(j = 0; j < PARAMS_N; j++) {
                        sum = 0;
                        sum += data->s[i*PARAMS_N + 0+v] * a_rows[0*PARAMS_N + j];
                        sum += data->s[i*PARAMS_N + 1+v] * a_rows[1*PARAMS_N + j];
                        sum += data->s[i*PARAMS_N + 2+v] * a_rows[2*PARAMS_N + j];
                        sum += data->s[i*PARAMS_N + 3+v] * a_rows[3*PARAMS_N + j];
                        out[i*PARAMS_N + j] += sum;
                    }
                    xSemaphoreGive(out_mutex[i]);
                }
            }
            #else
            for(i = 0; i < PARAMS_NBAR; i++) {
                for(j = 0; j < PARAMS_N; j++) {
                    sum = 0;
                    sum += data->s[i*PARAMS_N + 0+v] * a_rows[0*PARAMS_N + j];
                    sum += data->s[i*PARAMS_N + 1+v] * a_rows[1*PARAMS_N + j];
                    sum += data->s[i*PARAMS_N + 2+v] * a_rows[2*PARAMS_N + j];
                    sum += data->s[i*PARAMS_N + 3+v] * a_rows[3*PARAMS_N + j];
                    out[i*PARAMS_N + j] += sum;
                }
            }
            #endif
        v += 4;
        #endif

        if(v == v_max) {
            #ifndef USE_SINGLECORE
            if(data->id == 0)
                xEventGroupSetBits(frodo_macrify_evgp, EV_T0);
            else if(data->id == 1)
                xEventGroupSetBits(frodo_macrify_evgp, EV_T1);
            #else
            xEventGroupSetBits(frodo_macrify_evgp, EV_T0);
            #endif
            
            #ifdef USE_AES
            esp_aes_free(&ctx);
            #endif

            vTaskDelete(NULL);
        }
    }
}

int frodo_mul_add_sa_plus_e(uint16_t *out, const uint16_t *s, const uint16_t *e, const uint8_t *seed_A)
{ // Generate-and-multiply: generate matrix A (N x N) column-wise, multiply by s' on the left.
  // Inputs: s', e' (N_BAR x N)
  // Output: out = s'*A + e' (N_BAR x N)
    uint16_t i;
    
    for (i = 0; i < (PARAMS_N*PARAMS_NBAR); i += 2) {
        *((uint32_t*)&out[i]) = *((uint32_t*)&e[i]);
    }

    #ifndef USE_SINGLECORE
    for(i = 0; i < PARAMS_NBAR; i++) {
        out_mutex[i] = xSemaphoreCreateMutex();
    }
    #endif

    frodo_macrify_evgp = xEventGroupCreate();

    TaskData_t d0 = {0, out, s, seed_A, NULL};
    xTaskCreatePinnedToCore(task_mul_add_sa_plus_e, "Task s'*A+e' 0", 50000, (void *) &d0, tskIDLE_PRIORITY, NULL, 0);

    #ifndef USE_SINGLECORE
    TaskData_t d1 = {1, out, s, seed_A, NULL};
    xTaskCreatePinnedToCore(task_mul_add_sa_plus_e, "Task s'*A+e' 1", 50000, (void *) &d1, tskIDLE_PRIORITY, NULL, 1);

    EventBits_t bits = xEventGroupWaitBits(frodo_macrify_evgp, EV_T0 | EV_T1, pdTRUE, pdTRUE, portMAX_DELAY);
    if((bits & (EV_T0 | EV_T1)) == (EV_T0 | EV_T1)) {
        vEventGroupDelete(frodo_macrify_evgp);
        for(i = 0; i < PARAMS_NBAR; i++) {
            vSemaphoreDelete(out_mutex[i]);
        }
    }
    #else
    EventBits_t bits = xEventGroupWaitBits(frodo_macrify_evgp, EV_T0, pdTRUE, pdTRUE, portMAX_DELAY);
    if((bits & EV_T0) == EV_T0) {
        vEventGroupDelete(frodo_macrify_evgp);
    }
    #endif

    return 1;
}


void task_mul_bs(void* param) {
    TaskData_t* data = (TaskData_t*) param;
    uint16_t *out = data->out;

    uint16_t i, j, k;
    i = PARAMS_NBAR/2 * data->id;
    #ifdef USE_SINGLECORE
    const uint16_t i_max = PARAMS_NBAR;
    #else
    const uint16_t i_max = PARAMS_NBAR/2 * (1 + data->id);
    #endif

    while (1) {
        for (j = 0; j < PARAMS_NBAR; j++) {
            out[i*PARAMS_NBAR + j] = 0;
            for (k = 0; k < PARAMS_N; k++) {
                out[i*PARAMS_NBAR + j] += data->b[i*PARAMS_N + k] * data->s[j*PARAMS_N + k];
            }
            out[i*PARAMS_NBAR + j] = (uint32_t)(out[i*PARAMS_NBAR + j]) & ((1<<PARAMS_LOGQ)-1);
        }
        i++;

        if(i == i_max) {
            #ifndef USE_SINGLECORE
            if(data->id == 0)
                xEventGroupSetBits(frodo_macrify_evgp, EV_T0);
            else if(data->id == 1)
                xEventGroupSetBits(frodo_macrify_evgp, EV_T1);
            #else
            xEventGroupSetBits(frodo_macrify_evgp, EV_T0);
            #endif

            vTaskDelete(NULL);
        }
    }
}

void frodo_mul_bs(uint16_t *out, const uint16_t *b, const uint16_t *s) 
{ // Multiply by s on the right
  // Inputs: b (N_BAR x N), s (N x N_BAR)
  // Output: out = b*s (N_BAR x N_BAR)
    frodo_macrify_evgp = xEventGroupCreate();

    TaskData_t d0 = {0, out, s, NULL, b};
    xTaskCreatePinnedToCore(task_mul_bs, "Task (b*s) 0", 50000, (void *) &d0, tskIDLE_PRIORITY, NULL, 0);
    #ifndef USE_SINGLECORE
    TaskData_t d1 = {1, out, s, NULL, b};
    xTaskCreatePinnedToCore(task_mul_bs, "Task (b*s) 1", 50000, (void *) &d1, tskIDLE_PRIORITY, NULL, 1);
    EventBits_t bits = xEventGroupWaitBits(frodo_macrify_evgp, EV_T0 | EV_T1, pdTRUE, pdTRUE, portMAX_DELAY);
    if((bits & (EV_T0 | EV_T1)) == (EV_T0 | EV_T1))
        vEventGroupDelete(frodo_macrify_evgp);
    #else
    EventBits_t bits = xEventGroupWaitBits(frodo_macrify_evgp, EV_T0, pdTRUE, pdTRUE, portMAX_DELAY);
    if((bits & EV_T0) == EV_T0)
        vEventGroupDelete(frodo_macrify_evgp);
    #endif    
}


void task_mul_sb_plus_e(void* param) {
    TaskData_t* data = (TaskData_t*) param;
    uint16_t *out = data->out;

    uint16_t i, j, k;
    k = PARAMS_NBAR/2 * data->id;
    #ifdef USE_SINGLECORE
    const uint16_t k_max = PARAMS_NBAR;
    #else
    const uint16_t k_max = PARAMS_NBAR/2 * (1 + data->id);
    #endif

    while(1) {
        for (i = 0; i < PARAMS_NBAR; i++) {
            for (j = 0; j < PARAMS_N; j++) {
                out[k*PARAMS_NBAR + i] += data->s[k*PARAMS_N + j] * data->b[j*PARAMS_NBAR + i];
            }
            out[k*PARAMS_NBAR + i] = (uint32_t)(out[k*PARAMS_NBAR + i]) & ((1<<PARAMS_LOGQ)-1);
        }
        k++;

        if(k == k_max) {
            #ifndef USE_SINGLECORE
            if(data->id == 0)
                xEventGroupSetBits(frodo_macrify_evgp, EV_T0);
            else if(data->id == 1)
                xEventGroupSetBits(frodo_macrify_evgp, EV_T1);
            #else
            xEventGroupSetBits(frodo_macrify_evgp, EV_T0);
            #endif

            vTaskDelete(NULL);
        }
    }
}

void frodo_mul_add_sb_plus_e(uint16_t *out, const uint16_t *b, const uint16_t *s, const uint16_t *e) 
{ // Multiply by s on the left
  // Inputs: b (N x N_BAR), s (N_BAR x N), e (N_BAR x N_BAR)
  // Output: out = s*b + e (N_BAR x N_BAR)
    uint16_t i;

    for(i = 0; i < (PARAMS_NBAR*PARAMS_NBAR); i += 2) {
        *((uint32_t*)&out[i]) = *((uint32_t*)&e[i]);
    }

    frodo_macrify_evgp = xEventGroupCreate();

    TaskData_t d0 = {0, out, s, NULL, b};
    xTaskCreatePinnedToCore(task_mul_sb_plus_e, "Task (s*b + e) 0", 40000, (void *) &d0, tskIDLE_PRIORITY, NULL, 0);

    #ifndef USE_SINGLECORE
    TaskData_t d1 = {1, out, s, NULL, b};
    xTaskCreatePinnedToCore(task_mul_sb_plus_e, "Task (s*b + e) 1", 40000, (void *) &d1, tskIDLE_PRIORITY, NULL, 1);
    EventBits_t bits = xEventGroupWaitBits(frodo_macrify_evgp, EV_T0 | EV_T1, pdTRUE, pdTRUE, portMAX_DELAY);
    if((bits & (EV_T0 | EV_T1)) == (EV_T0 | EV_T1))
        vEventGroupDelete(frodo_macrify_evgp);
    #else
    EventBits_t bits = xEventGroupWaitBits(frodo_macrify_evgp, EV_T0, pdTRUE, pdTRUE, portMAX_DELAY);
    if((bits & EV_T0) == EV_T0)
        vEventGroupDelete(frodo_macrify_evgp);
    #endif
}


void frodo_add(uint16_t *out, const uint16_t *a, const uint16_t *b) 
{ // Add a and b
  // Inputs: a, b (N_BAR x N_BAR)
  // Output: c = a + b

    for (int i = 0; i < (PARAMS_NBAR*PARAMS_NBAR); i++) {
        out[i] = (a[i] + b[i]) & ((1<<PARAMS_LOGQ)-1);
    }
}


void frodo_sub(uint16_t *out, const uint16_t *a, const uint16_t *b) 
{ // Subtract a and b
  // Inputs: a, b (N_BAR x N_BAR)
  // Output: c = a - b

    for (int i = 0; i < (PARAMS_NBAR*PARAMS_NBAR); i++) {
        out[i] = (a[i] - b[i]) & ((1<<PARAMS_LOGQ)-1);
    }
}


void frodo_key_encode(uint16_t *out, const uint16_t *in) 
{ // Encoding
    unsigned int i, j, npieces_word = 8;
    unsigned int nwords = (PARAMS_NBAR*PARAMS_NBAR)/8;
    uint64_t temp, mask = ((uint64_t)1 << PARAMS_EXTRACTED_BITS) - 1;
    uint16_t* pos = out;

    for (i = 0; i < nwords; i++) {
        temp = 0;
        for(j = 0; j < PARAMS_EXTRACTED_BITS; j++) 
            temp |= ((uint64_t)((uint8_t*)in)[i*PARAMS_EXTRACTED_BITS + j]) << (8*j);
        for (j = 0; j < npieces_word; j++) { 
            *pos = (uint16_t)((temp & mask) << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS));  
            temp >>= PARAMS_EXTRACTED_BITS;
            pos++;
        }
    }
}


void frodo_key_decode(uint16_t *out, const uint16_t *in)
{ // Decoding
    unsigned int i, j, index = 0, npieces_word = 8;
    unsigned int nwords = (PARAMS_NBAR * PARAMS_NBAR) / 8;
    uint16_t temp, maskex=((uint16_t)1 << PARAMS_EXTRACTED_BITS) -1, maskq =((uint16_t)1 << PARAMS_LOGQ) -1;
    uint8_t  *pos = (uint8_t*)out;
    uint64_t templong;

    for (i = 0; i < nwords; i++) {
        templong = 0;
        for (j = 0; j < npieces_word; j++) {  // temp = floor(in*2^{-11}+0.5)
            temp = ((in[index] & maskq) + (1 << (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS - 1))) >> (PARAMS_LOGQ - PARAMS_EXTRACTED_BITS);
            templong |= ((uint64_t)(temp & maskex)) << (PARAMS_EXTRACTED_BITS * j);
            index++;
        }
	for(j = 0; j < PARAMS_EXTRACTED_BITS; j++) 
	    pos[i*PARAMS_EXTRACTED_BITS + j] = (templong >> (8*j)) & 0xFF;
    }
}