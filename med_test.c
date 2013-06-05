#include "med.h"
#include "med_priv.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>

#define MED_TAG_BW          0
#define MED_TAG_APP_ID      1

#define TEST_STATE(str,...) fprintf(stderr, "\n" str, ##__VA_ARGS__)
#define TEST_PASS(str, ...) TEST_STATE("PASS: " str, ##__VA_ARGS__)
#define TEST_FAIL(str, ...) TEST_STATE("FAIL: " str, ##__VA_ARGS__)

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
    /* Basic tests*/
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


        /* Setup */
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

        /* Sizeof */
        if (MED_IS_ERROR(med_sizeof(&enc, &len))) {
            TEST_FAIL("Sizeof failed at: %zu", len);
            return 1;
        }

        if (len != expected_len) {
            TEST_FAIL("Expected sizeof: %zu got %zu", expected_len, len);
            return 1;
        }

        TEST_PASS("Expected and returned len match: %zu", len);

        /* Input validation */
        if (MED_IS_OK(med_sizeof(NULL, &len))) {
            TEST_FAIL("NULL encoding");
            return 1;
        }
        TEST_PASS("NULL encoding");

        if (MED_IS_OK(med_sizeof(&enc, NULL))) {
            TEST_FAIL("NULL length");
            return 1;
        }
        TEST_PASS("NULL length");

        if (MED_IS_ERROR(med_encode(buf, &len, &enc))) {
            TEST_FAIL("Encode failed at: %zu", len);
            return 1;
        }

        if (0 != med_memcmp(expected_encoding, buf, expected_len)) {
            TEST_FAIL("The two buffers don't match:");
            TEST_FAIL("Expected: %zu\n", expected_len);
            med_dump_buf(expected_encoding, expected_len);
            TEST_FAIL("Received: %zu\n", len);
            med_dump_buf(buf, expected_len);
            return 1;
        }

        TEST_PASS("The two buffer match");

        if (MED_IS_OK(med_encode(NULL, &len, &enc))) {
            TEST_FAIL("NULL Buffer");
            return 1;
        }
        TEST_PASS("NULL Buffer");

        if (MED_IS_OK(med_encode(buf, NULL, &enc))) {
            TEST_FAIL("NULL Length");
            return 1;
        }
        TEST_PASS("NULL Length");

        if (MED_IS_OK(med_encode(buf, &len, NULL))) {
            TEST_FAIL("NULL encoding");
            return 1;
        }
        TEST_PASS("NULL encoding");
    }

    /* Test validation producer*/
    {
        size_t len = 0;
        md_enc_t enc = {0};
        md_producer_t prod1 = {0};
        md_producer_t prod2 = {0};
        md_pen_t pen = {0};
        md_tag_t bw_tag = {0};
        uint32_t bw = 0;
        med_err_t err;

        /* Setup */
        bw_tag.type = MED_TAG_BW;
        bw_tag.length = sizeof(bw);
        PUTLONG(&bw, 10);
        bw_tag.value = (uint8_t*)&bw;

        pen.upstream = &bw_tag;

        prod1.pens = &pen;
        prod2.pens = &pen;

        prod1.next = &prod2;

        enc.prods = &prod1;

        /* Two endpoint producers*/
        if (MED_IS_OK(err = med_sizeof(&enc, &len))) {
            TEST_FAIL("With two endpoints: %u", err);
            return 1;
        }
        TEST_PASS("With two endpoints");

        /* Enpoint and Network producer*/
        prod1.type = MED_PROD_NET;
        prod1.precedence = 1;
        if (MED_IS_ERROR(err = med_sizeof(&enc, &len))) {
            TEST_FAIL("Endpoint and Nework: %u", err);
            return 1;
        }
        TEST_PASS("Endpoint and Network");

        /* Two network producers same precedence*/
        prod2.type = MED_PROD_NET;
        prod2.precedence = 1;
        if (MED_IS_OK(err = med_sizeof(&enc, &len))) {
            TEST_FAIL("With two Networks same precedence: %u", err);
            return 1;
        }
        TEST_PASS("With two Networks same precedence");

        /* Two network producers same precedence*/
        prod2.precedence = 2;
        if (MED_IS_ERROR(err = med_sizeof(&enc, &len))) {
            TEST_FAIL("With two Networks different precedence: %u", err);
            return 1;
        }
        TEST_PASS("With two Networks different precedence");

        /* Endpoint wrong order */
        prod2.type = MED_PROD_EP;
        if (MED_IS_ERROR(err = med_sizeof(&enc, &len))
            || MED_PROD_EP != enc.prods->type
            || MED_PROD_NET != enc.prods->next->type) {
            TEST_FAIL("Endpoint wrong order: %u, 1: %u, 2: %u", 
                       err,
                       enc.prods->type,
                       enc.prods->next->type);
            return 1;
        }
        TEST_PASS("Endpoint wrong order");

        /* Endpoint right order */
        if (MED_IS_ERROR(err = med_sizeof(&enc, &len))
            || MED_PROD_EP != enc.prods->type
            || MED_PROD_NET != enc.prods->next->type) {
            TEST_FAIL("Endpoint right order: %u, 1: %u, 2: %u", 
                       err,
                       enc.prods->type,
                       enc.prods->next->type);
            return 1;
        }
        TEST_PASS("Endpoint right order");

    }

    /* Test validation pen*/
    {
        size_t len = 0;
        md_enc_t enc = {0};
        md_producer_t prod = {0};
        md_pen_t pen1 = {0};
        md_pen_t pen2 = {0};
        md_tag_t bw_tag = {0};
        uint32_t bw = 0;
        med_err_t err;

        /* Setup */
        bw_tag.type = MED_TAG_BW;
        bw_tag.length = sizeof(bw);
        PUTLONG(&bw, 10);
        bw_tag.value = (uint8_t*)&bw;

        pen1.upstream = &bw_tag;
        pen2.upstream = &bw_tag;

        pen1.next = &pen2;

        prod.pens = &pen1;

        enc.prods = &prod;

        /* Two standard pen*/
        if (MED_IS_OK(err = med_sizeof(&enc, &len))) {
            TEST_FAIL("With two standard pens: %u", err);
            return 1;
        }
        TEST_PASS("With two standard pens");

        /* One standard and vendor specific pen*/
        pen2.id = 1;
        if (MED_IS_ERROR(err = med_sizeof(&enc, &len))) {
            TEST_FAIL("One standard and vendor specific pen: %u", err);
            return 1;
        }
        TEST_PASS("One standard and vendor specific pen");

        /* Two vendor specific same pen*/
        pen1.id = 1;
        if (MED_IS_OK(err = med_sizeof(&enc, &len))) {
            TEST_FAIL("Two vendor specific same pen: %u", err);
            return 1;
        }
        TEST_PASS("Two vendor specific same pen");

        /* Two vendor specific different pen*/
        pen2.id = 2;
        if (MED_IS_ERROR(err = med_sizeof(&enc, &len))) {
            TEST_FAIL("Two vendor specific different pen: %u", err);
            return 1;
        }
        TEST_PASS("Two vendor specific different pen");

        /* Standard and vendor specific pen wrong order*/
        pen2.id = 0;
        if (MED_IS_ERROR(err = med_sizeof(&enc, &len))
            || MED_PEN_STD != prod.pens->id
            || MED_PEN_STD == prod.pens->next->id) {
            TEST_FAIL("Standard and vendor specific pen wrong order: %u", err);
            return 1;
        }
        TEST_PASS("Standard and vendor specific pen wrong order");

        /* Standard and vendor specific pen right order*/
        if (MED_IS_ERROR(err = med_sizeof(&enc, &len))
            || MED_PEN_STD != prod.pens->id
            || MED_PEN_STD == prod.pens->next->id) {
            TEST_FAIL("Standard and vendor specific pen right order: %u", err);
            return 1;
        }
        TEST_PASS("Standard and vendor specific pen right order");

        /* pen no directional block*/
        pen1.next = NULL;
        pen1.upstream = NULL;
        prod.pens = &pen1;
        enc.prods = &prod;
        if (MED_IS_OK(err = med_sizeof(&enc, &len))) {
            TEST_FAIL("Pen no directional block: %u", err);
            return 1;
        }
        TEST_PASS("Pen no directional block");

    }


    TEST_PASS("ALL TEST PASS");

    return 0;
}
