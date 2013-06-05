#include "med.h"
#include "med_priv.h"
#include "med_dbg.h"
#include <stddef.h>


/* ------------------------------------------------------------------
 *          Begin common
 * ------------------------------------------------------------------
 */
static med_err_t med_walk(md_enc_t* enc,
                          med_op_t* op,
                          void* ctx);

static med_err_t med_walk_direction(md_tag_t* tags,
                                    med_op_t* op,
                                    void* ctx);

int med_memcmp(const void* sp1, const void* sp2, size_t len)
{
    const unsigned char* p1 = sp1;
    const unsigned char* p2 = sp2;
    size_t i;

    for (i = 0; i < len; ++i) {
        if (p1[i] != p2[i]) {
            return p1[i] - p2[i];
        }
    }
    return 0;
}

void med_dump_buf(const void* sp, size_t len)
{
    size_t i;
    size_t count = 1;
    const uint8_t* p = sp;
    for (i = 0; i < len; ++i)
    {
        if (0 == (count%10)) {
            fprintf(stderr, "\n");
        }
        fprintf(stderr, "0x%02x ", p[i]);
        ++count;
    }
}

void* med_memcpy(void* dst, void* src, size_t len)
{
    size_t i;
    char* d = dst;
    const char* s = src;

    for (i = 0; i < len; ++i) {
        d[i] = s[i];
    }

    return dst;
}
/* ------------------------------------------------------------------
 *          End common
 * ------------------------------------------------------------------
 */

/* ------------------------------------------------------------------
 *          Begin sizeof callbacks
 * ------------------------------------------------------------------
 */
typedef struct med_sizeof_ctx_ {
    size_t* len;
}med_sizeof_ctx_t;

static med_err_t med_sizeof_preamble(md_enc_t* enc, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_sizeof_ctx_t* sizeof_ctx = (med_sizeof_ctx_t*)ctx;
    *(sizeof_ctx->len) += MED_VER_LEN;
    return MED_OK;
}

static med_err_t med_sizeof_prod(md_producer_t* prod, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_sizeof_ctx_t* sizeof_ctx = (med_sizeof_ctx_t*)ctx;
    *(sizeof_ctx->len) += MED_TLV_HDR + MED_PROD_LEN;
    return MED_OK;
}

static med_err_t med_sizeof_token(md_sec_t* tok, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_sizeof_ctx_t* sizeof_ctx = (med_sizeof_ctx_t*)ctx;
    *(sizeof_ctx->len) += MED_TLV_HDR + MED_SCHEME_LEN + tok->length;
    return MED_OK;
}

static med_err_t med_sizeof_vnd(md_pen_t* pen, void*ctx) 
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_sizeof_ctx_t* sizeof_ctx = (med_sizeof_ctx_t*)ctx;
    *(sizeof_ctx->len) += MED_TLV_HDR + MED_PEN_LEN;
    return MED_OK;
}

static med_err_t med_sizeof_direction(md_tag_t* tags, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_sizeof_ctx_t* sizeof_ctx = (med_sizeof_ctx_t*)ctx;
    *(sizeof_ctx->len) += MED_TLV_HDR;
    return MED_OK;
}

static med_err_t med_sizeof_tlv(md_tag_t* tag, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_sizeof_ctx_t* sizeof_ctx = (med_sizeof_ctx_t*)ctx;
    *(sizeof_ctx->len) += MED_TLV_HDR + tag->length;
    return MED_OK;
}


static med_op_t sizeof_op = { .tlv = med_sizeof_tlv,
                              .upstream = med_sizeof_direction,
                              .downstream = med_sizeof_direction,
                              .vnd = med_sizeof_vnd,
                              .token = med_sizeof_token,
                              .prod = med_sizeof_prod,
                              .preamble = med_sizeof_preamble};

med_err_t med_sizeof(md_enc_t* enc,
                     size_t* len)
{
    med_sizeof_ctx_t sizeof_ctx = {len};
    return med_walk(enc, &sizeof_op, &sizeof_ctx);
}
/* ------------------------------------------------------------------
 *          End sizeof callbacks
 * ------------------------------------------------------------------
 */
/* ------------------------------------------------------------------
 *          Begin encode callbacks
 * ------------------------------------------------------------------
 */
typedef struct med_encode_ctx_ {
    size_t* len;
    uint8_t* buf;
}med_encode_ctx_t;

static med_err_t med_encode_preamble(md_enc_t* enc, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_encode_ctx_t* encode_ctx = (med_encode_ctx_t*)ctx;
    if (*(encode_ctx->len) < MED_MIN_LENGTH) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    *(encode_ctx->buf) = MED_VERSION;
    encode_ctx->buf += MED_VER_LEN;
    *(encode_ctx->len) -= MED_VER_LEN;
    return MED_OK;
}

static med_err_t med_encode_prod(md_producer_t* prod, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_encode_ctx_t* encode_ctx = (med_encode_ctx_t*)ctx;
    if (*(encode_ctx->len) < (MED_TLV_HDR + MED_PROD_LEN)) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    PUTSHORT_MV(encode_ctx->buf, MED_PROD_TYPE);
    PUTSHORT_MV(encode_ctx->buf, MED_PROD_LEN);
    PUTLONG_MV(encode_ctx->buf, prod->precedence);
    *(encode_ctx->len) -= MED_TLV_HDR + MED_PROD_LEN;
    return MED_OK;
}


static med_err_t med_encode_token(md_sec_t* tok, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_encode_ctx_t* encode_ctx = (med_encode_ctx_t*)ctx;
    if (*(encode_ctx->len) < MED_TLV_HDR + MED_SCHEME_LEN + tok->length) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    PUTSHORT_MV(encode_ctx->buf, MED_SEC_TYPE);
    PUTSHORT_MV(encode_ctx->buf, MED_SCHEME_LEN + tok->length);
    PUTSHORT_MV(encode_ctx->buf, tok->scheme);
    med_memcpy(encode_ctx->buf, tok->payload, tok->length);
    *(encode_ctx->len) -= MED_TLV_HDR + MED_SCHEME_LEN + tok->length;
    return MED_OK;
}

static med_err_t med_encode_vnd(md_pen_t* pen, void*ctx) 
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_encode_ctx_t* encode_ctx = (med_encode_ctx_t*)ctx;
    if (*(encode_ctx->len) < MED_TLV_HDR + MED_PEN_LEN) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    PUTSHORT_MV(encode_ctx->buf, MED_VND_TYPE);
    PUTSHORT_MV(encode_ctx->buf, MED_PEN_LEN);
    PUTLONG_MV(encode_ctx->buf, pen->id);
    *(encode_ctx->len) -= MED_TLV_HDR + MED_PEN_LEN;
    return MED_OK;
}

static med_err_t med_encode_direction(md_tag_t* tags, uint16_t dir, void* ctx);

static med_err_t med_encode_upstream(md_tag_t* tags, void* ctx)
{
    return med_encode_direction(tags, MED_UP_TYPE, ctx);
}

static med_err_t med_encode_downstream(md_tag_t* tags, void* ctx)
{
    return med_encode_direction(tags, MED_DN_TYPE, ctx);
}

static med_err_t med_encode_direction(md_tag_t* tags, uint16_t dir, void* ctx)
{
    size_t len = 0;
    med_sizeof_ctx_t sizeof_ctx = {&len};
    med_err_t err = MED_OK;
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_encode_ctx_t* encode_ctx = (med_encode_ctx_t*)ctx;
    if (MED_IS_ERROR(err = med_walk_direction(tags, &sizeof_op, &sizeof_ctx))) {
        DEBUG_INVALID;
        return err;
    }
    /* Here we check that we have space for the whole block */
    if (*(encode_ctx->len) < MED_TLV_HDR + *(sizeof_ctx.len)) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    PUTSHORT_MV(encode_ctx->buf, dir);
    PUTSHORT_MV(encode_ctx->buf, *(sizeof_ctx.len));
    /* We decrement only the header and let the tags do their own work*/
    *(encode_ctx->len) -= MED_TLV_HDR;
    return MED_OK;
}

static med_err_t med_encode_tlv(md_tag_t* tag, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_encode_ctx_t* encode_ctx = (med_encode_ctx_t*)ctx;
    if (*(encode_ctx->len) < MED_TLV_HDR + tag->length) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    DEBUG_ERR("Type: %u, Length: %u, Value:", tag->type, tag->length);
    med_dump_buf(tag->value, tag->length);
    fprintf(stderr, "\n");
    PUTSHORT_MV(encode_ctx->buf, tag->type);
    PUTSHORT_MV(encode_ctx->buf, tag->length);
    med_memcpy(encode_ctx->buf, tag->value, tag->length);
    encode_ctx->buf += tag->length;
    *(encode_ctx->len) -= MED_TLV_HDR + tag->length;
    return MED_OK;
}


static med_op_t encode_op = { .tlv = med_encode_tlv,
                              .upstream = med_encode_upstream,
                              .downstream = med_encode_downstream,
                              .vnd = med_encode_vnd,
                              .token = med_encode_token,
                              .prod = med_encode_prod,
                              .preamble = med_encode_preamble};


med_err_t med_encode(uint8_t* buf,
                     size_t* len,
                     md_enc_t* enc)
{
    med_encode_ctx_t encode_ctx = {.len = len, .buf = buf};
    med_err_t err = MED_OK;
    if (MED_IS_ERROR(err = med_walk(enc, &encode_op, &encode_ctx))) {
        DEBUG_INVALID;
        return err;
    }
    return err;
}
/* ------------------------------------------------------------------
 *          End encode callbacks
 * ------------------------------------------------------------------
 */

/* ------------------------------------------------------------------
 *          Begin validate callbacks
 * ------------------------------------------------------------------
 */
typedef struct med_validate_ctx_ {
    size_t* len;
    uint8_t* buf;
}med_validate_ctx_t;

static med_err_t med_validate_preamble(md_enc_t* enc, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_validate_ctx_t* validate_ctx = (med_validate_ctx_t*)ctx;
    if (*(validate_ctx->len) < MED_MIN_LENGTH) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    *(validate_ctx->buf) = MED_VERSION;
    validate_ctx->buf += MED_VER_LEN;
    *(validate_ctx->len) -= MED_VER_LEN;
    return MED_OK;
}

static med_err_t med_validate_prod(md_producer_t* prod, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_validate_ctx_t* validate_ctx = (med_validate_ctx_t*)ctx;
    if (*(validate_ctx->len) < (MED_TLV_HDR + MED_PROD_LEN)) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    PUTSHORT_MV(validate_ctx->buf, MED_PROD_TYPE);
    PUTSHORT_MV(validate_ctx->buf, MED_PROD_LEN);
    PUTLONG_MV(validate_ctx->buf, prod->precedence);
    *(validate_ctx->len) -= MED_TLV_HDR + MED_PROD_LEN;
    return MED_OK;
}


static med_err_t med_validate_token(md_sec_t* tok, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_validate_ctx_t* validate_ctx = (med_validate_ctx_t*)ctx;
    if (*(validate_ctx->len) < MED_TLV_HDR + MED_SCHEME_LEN + tok->length) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    PUTSHORT_MV(validate_ctx->buf, MED_SEC_TYPE);
    PUTSHORT_MV(validate_ctx->buf, MED_SCHEME_LEN + tok->length);
    PUTSHORT_MV(validate_ctx->buf, tok->scheme);
    med_memcpy(validate_ctx->buf, tok->payload, tok->length);
    *(validate_ctx->len) -= MED_TLV_HDR + MED_SCHEME_LEN + tok->length;
    return MED_OK;
}

static med_err_t med_validate_vnd(md_pen_t* pen, void*ctx) 
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_validate_ctx_t* validate_ctx = (med_validate_ctx_t*)ctx;
    if (*(validate_ctx->len) < MED_TLV_HDR + MED_PEN_LEN) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    PUTSHORT_MV(validate_ctx->buf, MED_VND_TYPE);
    PUTSHORT_MV(validate_ctx->buf, MED_PEN_LEN);
    PUTLONG_MV(validate_ctx->buf, pen->id);
    *(validate_ctx->len) -= MED_TLV_HDR + MED_PEN_LEN;
    return MED_OK;
}

static med_err_t med_validate_direction(md_tag_t* tags, uint16_t dir, void* ctx);

static med_err_t med_validate_upstream(md_tag_t* tags, void* ctx)
{
    return med_validate_direction(tags, MED_UP_TYPE, ctx);
}

static med_err_t med_validate_downstream(md_tag_t* tags, void* ctx)
{
    return med_validate_direction(tags, MED_DN_TYPE, ctx);
}

static med_err_t med_validate_direction(md_tag_t* tags, uint16_t dir, void* ctx)
{
    size_t len = 0;
    med_sizeof_ctx_t sizeof_ctx = {&len};
    med_err_t err = MED_OK;
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_validate_ctx_t* validate_ctx = (med_validate_ctx_t*)ctx;
    if (MED_IS_ERROR(err = med_walk_direction(tags, &sizeof_op, &sizeof_ctx))) {
        DEBUG_INVALID;
        return err;
    }
    /* Here we check that we have space for the whole block */
    if (*(validate_ctx->len) < MED_TLV_HDR + *(sizeof_ctx.len)) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    PUTSHORT_MV(validate_ctx->buf, dir);
    PUTSHORT_MV(validate_ctx->buf, *(sizeof_ctx.len));
    /* We decrement only the header and let the tags do their own work*/
    *(validate_ctx->len) -= MED_TLV_HDR;
    return MED_OK;
}

static med_err_t med_validate_tlv(md_tag_t* tag, void* ctx)
{
    if (!ctx) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_validate_ctx_t* validate_ctx = (med_validate_ctx_t*)ctx;
    if (*(validate_ctx->len) < MED_TLV_HDR + tag->length) {
        DEBUG_INVALID;
        return MED_MEM;
    }
    DEBUG_ERR("Type: %u, Length: %u, Value:", tag->type, tag->length);
    med_dump_buf(tag->value, tag->length);
    fprintf(stderr, "\n");
    PUTSHORT_MV(validate_ctx->buf, tag->type);
    PUTSHORT_MV(validate_ctx->buf, tag->length);
    med_memcpy(validate_ctx->buf, tag->value, tag->length);
    validate_ctx->buf += tag->length;
    *(validate_ctx->len) -= MED_TLV_HDR + tag->length;
    return MED_OK;
}


static med_op_t validate_op = { .tlv = med_validate_tlv,
                              .upstream = med_validate_upstream,
                              .downstream = med_validate_downstream,
                              .vnd = med_validate_vnd,
                              .token = med_validate_token,
                              .prod = med_validate_prod,
                              .preamble = med_validate_preamble};


med_err_t med_validate(uint8_t* buf,
                     size_t* len,
                     md_enc_t* enc)
{
    med_validate_ctx_t validate_ctx = {.len = len, .buf = buf};
    med_err_t err = MED_OK;
    if (MED_IS_ERROR(err = med_walk(enc, &validate_op, &validate_ctx))) {
        DEBUG_INVALID;
        return err;
    }
    return err;
}
/* ------------------------------------------------------------------
 *          End validate callbacks
 * ------------------------------------------------------------------
 */
static med_err_t med_walk_direction(md_tag_t* tags,
                                    med_op_t* op,
                                    void* ctx)
{
    med_err_t err = MED_OK;
    if (!tags) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    while (tags) {
        if (!tags->value) {
            DEBUG_INVALID;
            return MED_BAD;
        }
        if (MED_IS_ERROR(err = op->tlv(tags, ctx))) {
            DEBUG_INVALID;
            return err;
        }
        tags = tags->next;
    }
    return err;
}

static med_err_t med_walk(md_enc_t* enc,
                          med_op_t* op,
                          void* ctx)
{
    med_err_t err = MED_OK;
    md_producer_t* prods;

    if (!enc) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    op->preamble(enc, ctx);
    prods = enc->prods;

    while (prods) {
        md_pen_t* pens = prods->pens;
        if (0 != prods->type
            && MED_IS_ERROR(err = op->prod(prods, ctx))) {
            DEBUG_INVALID;
            return err;
        }
        if (prods->token
            && MED_IS_ERROR(err = op->token(prods->token, ctx))) {
            DEBUG_INVALID;
            return err;
        }
        if (!pens) {
            DEBUG_INVALID;
            return MED_BAD;
        }
        while (pens) {
            if (!pens->upstream && !pens->downstream) {
                DEBUG_INVALID;
                return MED_BAD;
            }
            if (0 != pens->id
                && MED_IS_ERROR(err = op->vnd(pens, ctx))) {
                DEBUG_INVALID;
                return err;
            }
            if (pens->upstream
                && (MED_IS_ERROR(err = op->upstream(pens->upstream, ctx))
                    || MED_IS_ERROR(err = med_walk_direction(pens->upstream,
                                                          op,
                                                          ctx)))) {
                DEBUG_INVALID;
                return err;
            }
            if (pens->downstream
                && (MED_IS_ERROR(err = op->downstream(pens->downstream, ctx))
                    || MED_IS_ERROR(err = med_walk_direction(pens->downstream,
                                                          op,
                                                          ctx)))) {
                DEBUG_INVALID;
                return err;
            }
            pens = pens->next;
        }
        prods = prods->next;
    }
    return err;
}
#if 0
static med_err_t med_sizeof_direction(md_tag_t* tags,
                                      size_t* len) 
{
    if (!tags) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    while (tags) {
        if (!tags->value) {
            DEBUG_INVALID;
            return MED_BAD;
        }
        *len += MED_TLV_HDR + tags->length;
        tags = tags->next;
    }
}

med_err_t med_sizeof(const struct md_producer_* prods,
                     size_t* len)
{
    *len = 0;

    if (!prods) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    while (prods) {
        md_pen_t* pens = prods->pens;
        if (0 != prods->type) {
            *len += MED_TLV_HDR + MED_PROD_LEN;
        }
        if (prods->token) {
            *len += MED_TLV_HDR + MED_SCHEME_LEN + prods->token->length;
        }
        if (!pens) {
            DEBUG_INVALID;
            return MED_BAD;
        }
        while (pens) {
            if (!pens->upstream && !pens->downstream) {
                DEBUG_INVALID;
                return MED_BAD;
            }
            if (0 != pens->id) {
                *len += MED_TLV_HDR + MED_PEN_LEN;
            }
            if (pens->upstream
                && MED_IS_ERROR(med_sizeof_direction(pens->upstream, len))) {
                DEBUG_INVALID;
                return MED_BAD;
            }
            if (pens->downstream
                && MED_IS_ERROR(med_sizeof_direction(pens->downstream, len))) {
                DEBUG_INVALID;
                return MED_BAD;
            }
            pens = pens->next;
        }
        prods = prods->next;
    }
    return MED_OK;
}
#endif
