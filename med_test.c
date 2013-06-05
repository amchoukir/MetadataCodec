#include "med.h"
#include "med_priv.h"
#include <stdint.h>
#include <stdio.h>

#define MED_TAG_BW          0
#define MED_TAG_APP_ID      1

int main(void)
{
    md_producer_t prods = {0};
    md_pen_t pen = {0};
    md_tag_t bw_tag = {0};
    uint32_t bw = 10;
    md_tag_t appid_tag = {0};
    uint32_t appid = 144;
    size_t len = 0;
    size_t expected_len = 25;


    bw_tag.type = MED_TAG_BW;
    bw_tag.length = sizeof(bw);
    bw_tag.value = (uint8_t*)&bw;
    appid_tag.type = MED_TAG_APP_ID;
    appid_tag.length = sizeof(appid);
    appid_tag.value = (uint8_t*)&appid;

    pen.upstream = &bw_tag;
    pen.downstream = &appid_tag;

    prods.pens = &pen;

    if (MED_IS_ERROR(med_sizeof(&prods, &len))) {
        printf("\nSizeof failed at: %d", len);
        return 1;
    }

    if (len != expected_len) {
        printf("\nExpected sizeof: %d got %d", expected_len, len);
        return 1;
    }

    printf("\nExpected and returned len match: %d", len);

    return 0;
}
