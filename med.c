#include "med.h"
#include "med_priv.h"
#include "med_dbg.h"
#include <stddef.h>

/* Current encoding version*/
#define MED_VERSION 1
/* Version Length*/
#define MED_VER_LEN 1
/* Minimum length of encoding
 * Version and Upstream or 
 * Downstream TLV with one tag*/
#define MED_MIN_LENGTH 10
/* The HDR of a TLV is T+L*/
#define MED_TLV_HDR 4
/* Security scheme length*/
#define MED_SCHEME_LEN 2
/* Producer Marker Length */
#define MED_PROD_LEN 4
/* Vendor Marker Length*/
#define MED_PEN_LEN 4

static med_err_t med_walk(md_producer_t* prods,
                          med_op_t* op,
                          void* ctx);

static med_err_t med_walk_direction(md_tag_t* tags,
                                    med_op_t* op,
                                    void* ctx);

static void* med_memcpy(void* dst, void* src, size_t len);

/* ------------------------------------------------------------------
 *          Begin sizeof callbacks
 * ------------------------------------------------------------------
 */
typedef struct med_sizeof_ctx_ {
    size_t* len;
}med_sizeof_ctx_t;

static med_err_t med_sizeof_preamble(md_producer_t* prods, void* ctx)
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

med_err_t med_sizeof(md_producer_t* prods,
                     size_t* len)
{
    med_sizeof_ctx_t sizeof_ctx = {len};
    return med_walk(prods, &sizeof_op, &sizeof_ctx);
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

static med_err_t med_encode_preamble(md_producer_t* prods, void* ctx)
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
    PUTSHORT(encode_ctx->buf, MED_PROD_TYPE);
    PUTSHORT(encode_ctx->buf, MED_PROD_LEN);
    PUTLONG(encode_ctx->buf, prod->precedence);
    *(encode_ctx->len) -= MED_TLV_HDR + MED_PROD_LEN;
    return MED_OK;
}

static void* med_memcpy(void* dst, void* src, size_t len)
{
    size_t i;
    char* d = dst;
    const char* s = src;

    for (i = 0; i < len; ++i) {
        d[i] = s[i];
    }

    return dst;
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
    PUTSHORT(encode_ctx->buf, MED_SEC_TYPE);
    PUTSHORT(encode_ctx->buf, MED_SCHEME_LEN + tok->length);
    PUTSHORT(encode_ctx->buf, tok->scheme);
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
    PUTSHORT(encode_ctx->buf, MED_VND_TYPE);
    PUTSHORT(encode_ctx->buf, MED_PEN_LEN);
    PUTLONG(encode_ctx->buf, pen->id);
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
    PUTSHORT(encode_ctx->buf, dir);
    PUTSHORT(encode_ctx->buf, *(sizeof_ctx.len));
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
    PUTSHORT(encode_ctx->buf, tag->type);
    PUTSHORT(encode_ctx->buf, tag->length);
    med_memcpy(encode_ctx->buf, tag->value, tag->length);
    *(encode_ctx->len) -= MED_TLV_HDR + tag->length;
    return MED_OK;
}


static med_op_t encode_op = { .tlv = med_sizeof_tlv,
                              .upstream = med_encode_upstream,
                              .downstream = med_encode_downstream,
                              .vnd = med_encode_vnd,
                              .token = med_encode_token,
                              .prod = med_encode_prod,
                              .preamble = med_encode_preamble};
/* ------------------------------------------------------------------
 *          End encode callbacks
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

static med_err_t med_walk(md_producer_t* prods,
                          med_op_t* op,
                          void* ctx)
{
    med_err_t err = MED_OK;

    if (!prods) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    op->preamble(prods, ctx);

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
