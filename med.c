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

med_err_t med_validate(md_enc_t* enc);

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

void* med_memset(void *sp, int c, size_t len)
{
    char *p = sp;
    size_t i;

    for (i=0; i<len; i++) {
        p[i] = c;
    }

    return sp;
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


med_err_t med_init(md_enc_t* enc, med_mem_t* mem)
{
    if (!enc || !mem) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    med_memset(enc, 0, sizeof(md_enc_t));
    enc->type = MED_PROD_EP;
    enc->id = MED_PEN_STD;
    enc->dir = MED_UP_TYPE;
    med_memcpy(&(enc->mem), mem, sizeof(med_mem_t));
    return MED_OK;
}

static void lookup_producer(md_enc_t* enc,
                                 uint16_t type,
                                 uint32_t precedence,
                                 md_producer_t** prod_pred,
                                 md_producer_t** prod)
{
    md_producer_t* cur;
    md_producer_t* prev;

    *prod = NULL;
    *prod_pred = NULL;
    if (!enc->prods) {
        return;
    }

    prev = NULL;
    cur = enc->prods;
    while (cur) {
        if (cur->type == type
            && (MED_PROD_EP == type
                || cur->precedence == precedence)){
            *prod = cur;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
    *prod_pred = prev;
}

static void lookup_pen(md_enc_t* enc,
                            uint32_t id,
                            md_pen_t** pen_pred,
                            md_pen_t** pen)
{
    md_pen_t* cur;
    md_pen_t* prev;

    *pen_pred = NULL;
    *pen = NULL;
    if (!enc->prod) {
        return;
    }

    prev = NULL;
    cur = enc->prod->pens;
    while (cur) {
        if (cur->id == id) {
            *pen = cur;
            break;
        }
        prev = cur;
        cur = cur->next;
    }
    *pen_pred = prev;
}

static void lookup_tag(md_enc_t* enc,
                            uint16_t dir,
                            uint16_t type,
                            md_tag_t** tag)
{
    md_tag_t* tags;

    *tag = NULL;
    if (!enc->pen) {
        return;
    }
    tags = (MED_UP_TYPE == dir) ? enc->pen->upstream : enc->pen->downstream;
    while (tags) {
        if (tags->type == type) {
            *tag = tags;
            return;
        }
        tags = tags->next;
    }
}

static med_err_t set_or_create_producer(md_enc_t* enc)
{
    md_producer_t* prod_pred;
    md_producer_t* prod;

    /* This is the producer type not the tag type*/
    lookup_producer(enc, enc->type, enc->precedence, &prod_pred, &prod);
    if (!prod) {
        prod = enc->mem.alloc(sizeof(md_producer_t), enc->mem.alloc_ctx);
        if (!prod) {
            DEBUG_INVALID;
            return MED_MEM;
        }
        med_memset(prod, 0, sizeof(md_producer_t));
        prod->type = enc->type;
        prod->precedence = enc->precedence;
        if (MED_PROD_EP == enc->type) {
            prod->next = enc->prods;
            enc->prods = prod;
        } else if (!prod_pred) {
            enc->prods = prod;
        } else {
            prod_pred->next = prod;
        }
    }
    /* TODO: Change to cur_prod*/
    enc->prod = prod;

    return MED_OK;
}

med_err_t med_add_tag(md_enc_t* enc,
                      uint16_t type,
                      uint16_t length,
                      uint8_t* value)
{
    md_pen_t* pen_pred;
    md_pen_t* pen;
    md_tag_t* tag;
    med_err_t err;

    if (!enc || !length || !value) {
        return MED_BAD;
    }

    /* If we are adding to the same producer
     * skip producer lookup and allocation*/
    if (enc->prod
        && enc->prod->type == enc->type
        && enc->prod->precedence == enc->precedence) {
        goto pen;
    }

    if (MED_IS_ERROR(err = set_or_create_producer(enc))) {
        return err;
    }

pen:

    /* If we are adding for the same pen
     * skip the pen lookup and allocation*/
    if (enc->pen
        && enc->pen->id == enc->id) {
        goto tlv;
    }

    lookup_pen(enc, enc->id, &pen_pred, &pen);
    if (!pen) {
        pen = enc->mem.alloc(sizeof(md_pen_t), enc->mem.alloc_ctx);
        if (!pen) {
            DEBUG_INVALID;
            return MED_MEM;
        }
        med_memset(pen, 0, sizeof(md_pen_t));
        pen->id = enc->id;
        /* TODO: change prod to cur_prod*/
        if (MED_PEN_STD == enc->id){
            pen->next = enc->prod->pens;
            enc->prod->pens = pen;
        }else if (!pen_pred) {
            enc->prod->pens = pen;
        } else {
            pen_pred->next = pen;
        }

    }
    /* TODO: Change pen to cur_pen*/
    enc->pen = pen;

tlv:

    lookup_tag(enc, enc->dir, type, &tag);
    if (!tag) {
        tag = enc->mem.alloc(sizeof(md_tag_t), enc->mem.alloc_ctx);
        if (!tag) {
            DEBUG_INVALID;
            return MED_MEM;
        }
        med_memset(tag, 0, sizeof(md_tag_t));
        tag->type = type;
        if (enc->dir == MED_UP_TYPE) {
            tag->next = pen->upstream;
            pen->upstream = tag;
        } else {
            tag->next = pen->downstream;
            pen->downstream = tag;
        }
    } else {
        if (tag->length != length) {
            enc->mem.dealloc(tag->value, enc->mem.dealloc_ctx);
            tag->value = NULL;
        }
    }
    tag->length = length;
    if (!tag->value) {
        tag->value = enc->mem.alloc(length, enc->mem.alloc_ctx);
    }
    med_memcpy(tag->value, value, length);


    return MED_OK;
}
med_err_t med_add_tok(md_enc_t* enc,
                         uint16_t scheme,
                         uint16_t length,
                         uint8_t* payload)
{
    md_sec_t* token;
    med_err_t err;

    if (!enc || !length || !payload) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    /* If we are adding to the same producer
     * skip producer lookup and allocation*/
    if (!enc->prod
        || enc->prod->type != enc->type
        || enc->prod->precedence != enc->precedence) {
        if (MED_IS_ERROR(err = set_or_create_producer(enc))) {
            return err;
        }
    }

    if (!enc->prod->token) {
        token = enc->mem.alloc(sizeof(md_sec_t), enc->mem.alloc_ctx);
        med_memset(token, 0, sizeof(md_sec_t));
        enc->prod->token = token;
    } else {
        enc->mem.dealloc(enc->prod->token->payload, enc->mem.dealloc_ctx);
        enc->prod->token->payload = NULL;
    }
    token->scheme = scheme;
    token->length = length;
    token->payload = enc->mem.alloc(length, enc->mem.alloc_ctx);
    med_memcpy(token->payload, payload, length);

    return MED_OK;
}

med_err_t med_set_default(md_enc_t* enc)
{
    if (!enc) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    enc->type = MED_PROD_EP;
    enc->id = MED_PEN_STD;
    enc->dir = MED_UP_TYPE;

    return MED_OK;
}

med_err_t med_set_ep(md_enc_t* enc)
{
    if (!enc) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    enc->type = MED_PROD_EP;
    enc->precedence = 0;

    return MED_OK;
}

med_err_t med_set_net(md_enc_t* enc, uint32_t precedence)
{
    if (!enc) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    enc->type = MED_PROD_NET;
    enc->precedence = precedence;

    return MED_OK;
}

med_err_t med_set_std(md_enc_t* enc)
{
    if (!enc) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    enc->id = MED_PEN_STD;

    return MED_OK;
}

med_err_t med_set_vnd(md_enc_t* enc, uint32_t id)
{
    if (!enc) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    enc->id = id;

    return MED_OK;
}

med_err_t med_set_upstream(md_enc_t* enc)
{
    if (!enc) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    enc->dir = MED_UP_TYPE;

    return MED_OK;
}

med_err_t med_set_downstream(md_enc_t* enc)
{
    if (!enc) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    enc->dir = MED_DN_TYPE;

    return MED_OK;
}

uint8_t  med_is_ep(md_enc_t* enc)
{
    if (!enc)
    {
        return -1;
    }
    return enc->type == MED_PROD_EP;
}

uint8_t  med_is_net(md_enc_t* enc)
{
    if (!enc)
    {
        return -1;
    }
    return enc->type == MED_PROD_NET;
}

uint8_t  med_is_std(md_enc_t* enc)
{
    if (!enc)
    {
        return -1;
    }
    return enc->id == MED_PEN_STD;
}

uint8_t  med_is_vnd(md_enc_t* enc)
{
    if (!enc)
    {
        return -1;
    }
    return enc->id != MED_PEN_STD;
}

uint8_t  med_is_up(md_enc_t* enc)
{
    if (!enc)
    {
        return -1;
    }
    return enc->dir == MED_UP_TYPE;
}

uint8_t  med_is_dn(md_enc_t* enc)
{
    if (!enc)
    {
        return -1;
    }
    return enc->dir == MED_DN_TYPE;
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
    med_sizeof_ctx_t* sizeof_ctx = (med_sizeof_ctx_t*)ctx;
    *(sizeof_ctx->len) += MED_VER_LEN;
    return MED_OK;
}

static med_err_t med_sizeof_prod(md_producer_t* prod, void* ctx)
{
    if (MED_PROD_EP == prod->type) {
        return MED_OK;
    }
    med_sizeof_ctx_t* sizeof_ctx = (med_sizeof_ctx_t*)ctx;
    *(sizeof_ctx->len) += MED_TLV_HDR + MED_PROD_LEN;
    return MED_OK;
}

static med_err_t med_sizeof_token(md_sec_t* tok, void* ctx)
{
    if (!tok) {
        return MED_OK;
    }
    med_sizeof_ctx_t* sizeof_ctx = (med_sizeof_ctx_t*)ctx;
    *(sizeof_ctx->len) += MED_TLV_HDR + MED_SCHEME_LEN + tok->length;
    return MED_OK;
}

static med_err_t med_sizeof_vnd(md_pen_t* pen, void*ctx) 
{

    if (MED_PEN_STD == pen->id) {
        return MED_OK;
    }
    med_sizeof_ctx_t* sizeof_ctx = (med_sizeof_ctx_t*)ctx;
    *(sizeof_ctx->len) += MED_TLV_HDR + MED_PEN_LEN;
    return MED_OK;
}

static med_err_t med_sizeof_direction(md_tag_t* tags, void* ctx)
{
    if (!tags) {
        return MED_OK;
    }
    med_sizeof_ctx_t* sizeof_ctx = (med_sizeof_ctx_t*)ctx;
    *(sizeof_ctx->len) += MED_TLV_HDR;
    return MED_OK;
}

static med_err_t med_sizeof_tlv(md_tag_t* tag, void* ctx)
{
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
    med_err_t err;
    if (!enc || !len) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    if (MED_IS_ERROR(err = med_validate(enc))) {
        DEBUG_INVALID;
        return err;
    }
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
    if (MED_PROD_EP == prod->type) {
        return MED_OK;
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
    if (!tok) {
        return MED_OK;
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
    if (MED_PEN_STD == pen->id) {
        return MED_OK;
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

    if (!tags) {
        return MED_OK;
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
    med_err_t err;
    if (!buf || !len || !enc) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    if (MED_IS_ERROR(err = med_validate(enc))) {
        DEBUG_INVALID;
        return err;
    }
    return med_walk(enc, &encode_op, &encode_ctx);
}
/* ------------------------------------------------------------------
 *          End encode callbacks
 * ------------------------------------------------------------------
 */

/* ------------------------------------------------------------------
 *          Begin validate callbacks
 * ------------------------------------------------------------------
 */
static med_err_t med_validate_preamble(md_enc_t* enc, void* ctx)
{
    md_producer_t* current;
    md_producer_t* tmp;
    uint8_t ep_found = 0;

    /* Check for duplicate endpoint section
     * and for producer with duplicate precedence*/
    current = enc->prods;
    ep_found = MED_PROD_EP == current->type ? 1 : 0;
    while (current) {
        tmp = current->next;
        while (tmp) {
            if (MED_PROD_EP == tmp->type) {
                DEBUG_ERR("ep_found: %d", ep_found);
                if(ep_found) {
                    DEBUG_INVALID;
                    return MED_BAD;
                }
                ep_found = 1;
            }
            if (tmp->precedence == current->precedence) {
                DEBUG_INVALID;
                return MED_BAD;
            }
            tmp = tmp->next;
        }
        current = current->next;
    }

    /* Bring the endpoint as first producer*/
    if (ep_found && MED_PROD_EP != enc->prods->type) {
        DEBUG_ERR("Endpoint wrong order");
        tmp = enc->prods;
        current = tmp->next;
        while (current) {
            if (MED_PROD_EP == current->type) {
                tmp->next = current->next;
                current->next = enc->prods;
                enc->prods = current;
                break;
            }
            tmp = current;
            current = current->next;
        }
    }

    return MED_OK;
}

static med_err_t med_validate_prod(md_producer_t* prod, void* ctx)
{
    md_pen_t* current;
    md_pen_t* tmp;
    uint8_t std_found = 0;

    current = prod->pens;
    if (!current) {
        DEBUG_INVALID;
        return MED_BAD;
    }

    /* Check for duplicate standard or vendor specific
     * subsection*/
    while (current) {
        tmp = current->next;
        while (tmp) {
            if (MED_PEN_STD == tmp->id) {
                std_found = 1;
            }
            if (tmp->id == current->id) {
                DEBUG_INVALID;
                return MED_BAD;
            }
            tmp = tmp->next;
        }
        current = current->next;
    }

    /* Bring the standard section at the beginning*/
    if (std_found && MED_PEN_STD != prod->pens->id) {
        tmp = prod->pens;
        current = tmp->next;
        while (current) {
            if (MED_PEN_STD == current->id) {
                tmp->next = current->next;
                current->next = prod->pens;
                prod->pens = current;
                break;
            }
            tmp = current;
            current = current->next;
        }
    }

    return MED_OK;
}


static med_err_t med_validate_token(md_sec_t* tok, void* ctx)
{
    if (!tok) {
        return MED_OK;
    }
    if (!tok->length || !tok->payload) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    return MED_OK;
}

static med_err_t med_validate_vnd(md_pen_t* pen, void*ctx) 
{
    if (!pen->upstream && !pen->downstream) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    return MED_OK;
}


static med_err_t med_validate_direction(md_tag_t* tags, void* ctx)
{
    /* There is nothing to validate per direction*/
    return MED_OK;
}

static med_err_t med_validate_tlv(md_tag_t* tag, void* ctx)
{
    if (!tag->length || !tag->value) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    return MED_OK;
}


static med_op_t validate_op = { .tlv = med_validate_tlv,
                              .upstream = med_validate_direction,
                              .downstream = med_validate_direction,
                              .vnd = med_validate_vnd,
                              .token = med_validate_token,
                              .prod = med_validate_prod,
                              .preamble = med_validate_preamble};


med_err_t med_validate(md_enc_t* enc)
{
    med_err_t err = MED_OK;
    if (!enc) {
        DEBUG_INVALID;
        return MED_BAD;
    }
    if (MED_IS_ERROR(err = med_walk(enc, &validate_op, NULL))) {
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

    while (tags) {
        if (MED_IS_ERROR(err = op->tlv(tags, ctx))) {
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

    if (MED_IS_ERROR(err = op->preamble(enc, ctx))) {
            return err;
    }
    prods = enc->prods;

    while (prods) {
        md_pen_t* pens = prods->pens;
        if (MED_IS_ERROR(err = op->prod(prods, ctx))) {
            return err;
        }
        if (MED_IS_ERROR(err = op->token(prods->token, ctx))) {
            return err;
        }
        while (pens) {
            if (MED_IS_ERROR(err = op->vnd(pens, ctx))) {
                return err;
            }
            if (MED_IS_ERROR(err = op->upstream(pens->upstream, ctx))
                || MED_IS_ERROR(err = med_walk_direction(pens->upstream,
                                                         op,
                                                         ctx))) {
                return err;
            }
            if (MED_IS_ERROR(err = op->downstream(pens->downstream, ctx))
                    || MED_IS_ERROR(err = med_walk_direction(pens->downstream,
                                                          op,
                                                          ctx))) {
                return err;
            }
            pens = pens->next;
        }
        prods = prods->next;
    }
    return err;
}

/* Public walking function */
typedef struct {
    med_walk_callbacks_t const*callbacks;
    void *user_context;
} med_callback_user_t;

/* -------------------------------------------------------------------------- */
static med_err_t _cb_prod(md_producer_t* prod, void* ctx)
{
    med_callback_user_t *cb = (typeof(cb))ctx;
    if (NULL != cb->callbacks->prod) {
        (void)cb->callbacks->prod(prod->precedence, cb->user_context);
    }
    return MED_OK;
}
/* -------------------------------------------------------------------------- */
static med_err_t _cb_token(md_sec_t* sec, void* ctx)
{
    med_callback_user_t *cb = (typeof(cb))ctx;
    if (NULL != cb->callbacks->token) {
        (void)cb->callbacks->token(sec->length,sec->scheme,sec->payload,
                                                        cb->user_context);
    }
    return MED_OK;
}
/* -------------------------------------------------------------------------- */
static med_err_t _cb_preamble(md_enc_t* enc, void* ctx)
{
    med_callback_user_t *cb = (typeof(cb))ctx;
    if (NULL != cb->callbacks->preamble) {
        (void)cb->callbacks->preamble(cb->user_context);
    }
    return MED_OK;
}
/* -------------------------------------------------------------------------- */
static med_err_t _cb_downstream(md_tag_t* taglist, void* ctx)
{
    med_callback_user_t *cb = (typeof(cb))ctx;
    if (NULL != cb->callbacks->downstream) {
        (void)cb->callbacks->downstream(cb->user_context);
    }
    return MED_OK;
}
/* -------------------------------------------------------------------------- */
static med_err_t _cb_upstream(md_tag_t* taglist, void* ctx)
{
    med_callback_user_t *cb = (typeof(cb))ctx;
    if (NULL != cb->callbacks->upstream) {
        (void)cb->callbacks->upstream(cb->user_context);
    }
    return MED_OK;
}
/* -------------------------------------------------------------------------- */
static med_err_t _cb_vnd(md_pen_t* pen, void* ctx)
{
    med_callback_user_t *cb = (typeof(cb))ctx;
    if (NULL != cb->callbacks->vnd) {
        (void)cb->callbacks->vnd(pen->id,cb->user_context);
    }
    return MED_OK;
}
/* -------------------------------------------------------------------------- */
static med_err_t _cb_tlv(md_tag_t* tag, void* ctx)
{
    med_callback_user_t *cb = (typeof(cb))ctx;
    if (NULL != cb->callbacks->tlv) {
        (void)cb->callbacks->tlv(tag->type,tag->length,tag->value,
                                               cb->user_context);
    }
    return MED_OK;
}
/* -------------------------------------------------------------------------- */
med_err_t med_walk_public(md_enc_t const *enc, med_walk_callbacks_t const *cb,void *ctx)
{
    med_callback_user_t user_callbacks;
    user_callbacks.callbacks = cb;
    user_callbacks.user_context = ctx;

    static const med_op_t operations = {
        .tlv        = _cb_tlv,
        .upstream   = _cb_upstream,
        .downstream = _cb_downstream,
        .vnd        = _cb_vnd,
        .token      = _cb_token,
        .prod       = _cb_prod,
        .preamble   = _cb_preamble,
    };

    return med_walk(enc,&operations,&user_callbacks);
}
