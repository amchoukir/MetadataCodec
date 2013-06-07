#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include "med.h"
#include "med_priv.h"

void random_add_tag(md_enc_t *enc)
{
    uint16_t t,l;
    char value[512];
    memset(value,rand() & 255,512);
    t = rand() & 0xFFFF;
    l = rand() & 511;
    printf("-- %s (l:%u)",__func__,l);
    if (0 == l) l = 1;
    if (MED_IS_OK(med_add_tag(enc,t,l,value))) {
        printf(" ... OK\n");
    } else {
        printf(" ... FAILED!!!\n");
    }
}

void random_set_vnd(md_enc_t *enc)
{
    printf("-- %s",__func__);
    if (MED_IS_OK(med_set_vnd(enc,rand() & 0xFFFFFFFF))) {
        printf(" ... OK\n");
    } else {
        printf(" ... FAILED!!!\n");
    }
}

void random_set_up(md_enc_t *enc)
{
    printf("-- %s",__func__);
    if (MED_IS_OK(med_set_upstream(enc))) {
        printf(" ... OK\n");
    } else {
        printf(" ... FAILED!!!\n");
    }
}

void random_set_dn(md_enc_t *enc)
{
    printf("-- %s",__func__);
    if (MED_IS_OK(med_set_downstream(enc))) {
        printf(" ... OK\n");
    } else {
        printf(" ... FAILED!!!\n");
    }
}

void random_set_net(md_enc_t *enc)
{
    printf("-- %s",__func__);
    if (MED_IS_OK(med_set_net(enc,rand() & 0xFFFFFFFF /* precedence */))) {
        printf(" ... OK\n");
    } else {
        printf(" ... FAILED!!!\n");
    }
}

void random_add_tok(md_enc_t *enc)
{
    uint16_t type = rand() & 0xFFFF;
    char payload[512];
    memset(payload,rand() & 255,512);
    uint16_t length = rand() & 511;
    printf("-- %s",__func__);
    if (MED_IS_OK(med_add_tok(enc,type,length,payload))) {
        printf(" ... OK\n");
    } else {
        printf(" ... FAILED!!!\n");
    }
}

static void* test_alloc(size_t size, void* ctx)
{
    return malloc(size);
}

static void test_dealloc(void* ptr, void* ctx)
{
    free(ptr);
}

typedef void(*random_action)(md_enc_t*);

int main (int argc, char *argv[])
{
    med_mem_t mem = { 0 };
    md_enc_t  enc = { 0 };

    srand(time(NULL));

    mem.alloc = test_alloc;
    mem.dealloc = test_dealloc;
    med_init(&enc, &mem);

    random_action actions[] = {
        random_add_tag,
    //    random_set_vnd,
    //    random_set_up,
    //    random_set_dn,
    //    random_set_net,
    //    random_add_tok,
    };
    //med_set_std
    //med_set_ep

    unsigned int loops = 512;
    while (--loops) {
        actions[rand()%(sizeof(actions)/sizeof(actions[0]))](&enc);
        fflush(stdout);
    }
    size_t len,length;
    if (MED_IS_ERROR(med_sizeof(&enc,&len))) {
        printf("med_sizeof failed.\n");
        return 1;
    }
    length = len;
    printf("%u bytes required to encode\n",(unsigned int)length);
    char *buffer = malloc(len);
    assert(NULL != buffer);
    if (MED_IS_OK(med_encode(buffer,&len,&enc))) {
        med_dump_buf(buffer,length);
    } else {
        printf("med_encode failed.\n");
    }

    return 0;
}



/// gcc -Wall -O0 -g -o test  med.c med_decode.c  test.c -DMED_DEBUG
