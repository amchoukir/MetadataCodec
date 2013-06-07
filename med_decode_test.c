#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>
#include "med_priv.h"
#include "med.h"
int test_decode(void)
{
    #if 0
    const uint8_t encoded_buffer[] = {
    0x01, /* version */
    0x00,MED_SEC_TYPE,
    0x00,0x01, /* sec payload len */
    #if 1
    0x01,0x02, /* security scheme */
    0x12, /* sec payload */
    #endif
    };
    #endif
    #if 1
    uint8_t encoded_buffer[] = {
        MED_VERSION, MED_UP_TYPE >> 8, MED_UP_TYPE,  0x00, 0x08,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x0A, MED_DN_TYPE >> 8, MED_DN_TYPE,
        0x00, 0x08, 0x00, 0x01, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x90, MED_PROD_TYPE >> 8, MED_PROD_TYPE,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x08,
        MED_VND_TYPE >> 8, MED_VND_TYPE,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x09,
        MED_UP_TYPE >> 8, MED_UP_TYPE,  0x00, 0x08,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x0A, MED_DN_TYPE >> 8, MED_DN_TYPE,
        0x00, 0x08, 0x00, 0x01, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x90
    };
    #endif
    #if 0
    uint8_t encoded_buffer[] = {
        MED_VERSION, MED_PROD_TYPE >> 8, MED_PROD_TYPE,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x08,
        MED_VND_TYPE >> 8, MED_VND_TYPE,
        0x00, 0x04, 0x00, 0x00, 0x00, 0x09,
        MED_UP_TYPE >> 8, MED_UP_TYPE,  0x00, 0x08,
        0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
        0x00, 0x0A, MED_DN_TYPE >> 8, MED_DN_TYPE,
        0x00, 0x08, 0x00, 0x01, 0x00, 0x04,
        0x00, 0x00, 0x00, 0x90
    };
    #endif

    md_producer_t *head = NULL;
    size_t buffer_length = sizeof(encoded_buffer);
    med_err_t result = med_decode_producers(encoded_buffer,&buffer_length,&head,NULL);
    printf("RESULT:%d\n",result);
    md_enc_t enc;
    enc.prods = head;
    size_t len = 0;
    if (MED_IS_ERROR(med_sizeof(&enc, &len))) {
        printf("\nSizeof failed at: %zu\n", len);
        return 1;
    }
    printf("\nNeed %zu bytes to encode\n",len);
    size_t needed = len;
    uint8_t* buf = malloc(needed);
    if (MED_IS_ERROR(med_encode(buf, &len, &enc))) {
        printf("Encode failed at: %zu\n", len);
        return 1;
    }
    unsigned int i;
    for (i = 0; i < needed; i++) {
        printf("%02X ",buf[i]);
        if (((i + 1) % 16) == 0)
            printf("\n");
    }
    printf("\n");
    if (0 == med_memcmp(buf,encoded_buffer,needed)) {
        printf("YOUPI!!!!\n");
    }

    return 0;
}
//// gcc -Wall -O3 -o med_decode_test med_decode_test.c med_decode.c
