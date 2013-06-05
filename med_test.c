#include "med.h"
#include "med_priv.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#define MED_TAG_BW          0
#define MED_TAG_APP_ID      1

#if 0
static void* test_alloc(size_t size, void* ctx)
{
    return malloc(size);
}

static void test_dealloc(void* ptr, void* ctx)
{
    free(ptr);
}
#endif

int main(void)
{
    md_enc_t enc = {0};
    md_producer_t prods = {0};
    md_pen_t pen = {0};
    md_tag_t bw_tag = {0};
    uint32_t bw = 0;
    md_tag_t appid_tag = {0};
    uint32_t appid = 0;
    size_t len = 0;
    size_t expected_len = 25;
    /* version | UP [bw=10] | DN[appid=144] */
    uint8_t expected_encoding[25] = { MED_VERSION, MED_UP_TYPE >> 8, MED_UP_TYPE,
                                      0x00, 0x08, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00,
                                      0x00, 0x0A, MED_DN_TYPE >> 8, MED_DN_TYPE,
                                      0x00, 0x08, 0x00, 0x01, 0x00, 0x04, 0x00,
                                      0x00, 0x00, 0x90
                                    };
    uint8_t buf[25] = {0};
    //med_mem_t mem = {0};


    bw_tag.type = MED_TAG_BW;
    bw_tag.length = sizeof(bw);
    PUTLONG(&bw, 10);
    bw_tag.value = (uint8_t*)&bw;
    appid_tag.type = MED_TAG_APP_ID;
    PUTLONG(&appid, 144);
    appid_tag.length = sizeof(appid);
    appid_tag.value = (uint8_t*)&appid;

    pen.upstream = &bw_tag;
    pen.downstream = &appid_tag;

    prods.pens = &pen;

    enc.prods = &prods;

    if (MED_IS_ERROR(med_sizeof(&enc, &len))) {
        fprintf(stderr,"\nSizeof failed at: %zu", len);
        return 1;
    }

    if (len != expected_len) {
        fprintf(stderr,"\nExpected sizeof: %zu got %zu", expected_len, len);
        return 1;
    }

    fprintf(stderr,"\nExpected and returned len match: %zu", len);


    if (MED_IS_ERROR(med_encode(buf, &len, &enc))) {
        fprintf(stderr,"\nEncode failed at: %zu", len);
        return 1;
    }

    if (0 != med_memcmp(expected_encoding, buf, expected_len)) {
            fprintf(stderr,"\nThe two buffers don't match:");
            fprintf(stderr,"\nExpected: %zu\n", expected_len);
            med_dump_buf(expected_encoding, expected_len);
            fprintf(stderr,"\nReceived: %zu\n", len);
            med_dump_buf(buf, expected_len);
            return 1;
    }

    fprintf(stderr,"\n The two buffer match");

    return 0;
}
