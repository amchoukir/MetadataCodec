#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdbool.h>

#include "med_priv.h"

#ifndef PUTSHORT
#define PUTSHORT(ptr,val) {                         \
    unsigned char *_ptr = (unsigned char *)(ptr);   \
    uint16_t       _val = (uint16_t)(val);          \
    _ptr[0] = (_val >> 8) & 0xFF;                   \
    _ptr[1] = (_val >> 0) & 0xFF;                   \
}
#endif

#ifndef PUTLONG
#define PUTLONG(ptr,val) {                          \
    unsigned char *_ptr = (unsigned char *)(ptr);   \
    uint32_t       _val = (uint32_t)(val);          \
    _ptr[0] = (_val >> 24) & 0xFF;                  \
    _ptr[1] = (_val >> 16) & 0xFF;                  \
    _ptr[2] = (_val >>  8) & 0xFF;                  \
    _ptr[3] = (_val >>  0) & 0xFF;                  \
}
#endif

#ifndef GETSHORT
#define GETSHORT(ptr) ({                            \
    unsigned char *_ptr = (unsigned char *)(ptr);   \
    uint16_t val = (_ptr[0] << 8) | (_ptr[1]);      \
    val;                                            \
})
#endif

#ifndef GETLONG
#define GETLONG(ptr) ({                                 \
    unsigned char *_ptr = (unsigned char *)(ptr);       \
    uint32_t val = (_ptr[0] << 24) | (_ptr[1] << 16);   \
    val |= (_ptr[2] << 8) | (_ptr[3]);                  \
    val;                                                \
})
#endif

#define REPORT_FAILURE { printf("FAILURE#%u\n",__LINE__); return false;}
#define DECODE_DBG(fmt,...) \
    { printf("[%-28s:%4u] " fmt "\n",__func__,__LINE__,##__VA_ARGS__); }
void freeprod(med_mem_t const *mem,md_producer_t *prod);
/* -------------------------------------------------------------------------- */
void *_malloc(size_t size, void *__unused__)
{
    return malloc(size);
}
/* -------------------------------------------------------------------------- */
void _dealloc(void *ptr, void *__unused__)
{
    return free(ptr);
}
/* -------------------------------------------------------------------------- */
static bool consume1(uint8_t *value, uint8_t const **data, size_t *remain)
{
    const size_t size = 1;
    if (size <= *remain) {
        if (NULL != value) {
            *value = **data;
        }
        *data += size;
        *remain -= size;
        return true;
    }
    return false;
}
/* -------------------------------------------------------------------------- */
static bool consume2(uint16_t *value, uint8_t const **data, size_t *remain)
{
    const size_t size = 2;
    if (size <= *remain) {
        if (NULL != value) {
            *value = GETSHORT(*data);
        }
        *data += size;
        *remain -= size;
        return true;
    }
    return false;
}
/* -------------------------------------------------------------------------- */
static bool consume4(uint32_t *value, uint8_t const **data, size_t *remain)
{
    const size_t size = 4;
    if (size <= *remain) {
        if (NULL != value) {
            *value = GETLONG(*data);
        }
        *data += size;
        *remain -= size;
        return true;
    }
    return false;
}
/* -------------------------------------------------------------------------- */
static bool consumeX(size_t size, uint8_t const **data, size_t *remain)
{
    if (size <= *remain) {
        *data += size;
        *remain -= size;
        return true;
    }
    return false;
}
#define medmemcpy memcpy
#define medmemset memset
/* -------------------------------------------------------------------------- */
static md_pen_t* _create_pen(med_mem_t const *mem)
{
    md_pen_t *pen = mem->alloc(sizeof(md_pen_t),mem->alloc_ctx);
    if (NULL != pen) {
        medmemset(pen, 0, sizeof(md_pen_t));
    }
    return pen;
}
/* -------------------------------------------------------------------------- */
static md_sec_t* _create_security(med_mem_t const *mem)
{
    md_sec_t *sec = mem->alloc(sizeof(md_sec_t),mem->alloc_ctx);
    if (NULL != sec) {
        medmemset(sec, 0, sizeof(md_sec_t));
    }
    return sec;
}
/* -------------------------------------------------------------------------- */
static void freetag(med_mem_t const *mem,md_tag_t *tag)
{
    md_tag_t *next = tag->next;
    if (NULL != tag->value) {
        mem->dealloc(tag->value,mem->dealloc_ctx);
        tag->value = NULL;
    }
    medmemset(tag,0xA5,sizeof(*tag));
    mem->dealloc(tag,mem->dealloc_ctx);
    if (NULL != next) {
        freetag(mem,next);
    }
}
/* -------------------------------------------------------------------------- */
static md_tag_t* _create_tag(med_mem_t const *mem)
{
    md_tag_t *tag = mem->alloc(sizeof(md_tag_t),mem->alloc_ctx);
    if (NULL != tag) {
        medmemset(tag,0,sizeof(*tag));
    }
    return tag;
}
/* -------------------------------------------------------------------------- */
static bool _decode_tlvs(med_mem_t const *mem, md_tag_t **const list_head,
                                  uint8_t const **buffer, size_t block_length)
{
    while (0 != block_length) {
        uint16_t t,l;
        if (!consume2(&t,buffer,&block_length)) {
            REPORT_FAILURE;
        }
        if (!consume2(&l,buffer,&block_length)) {
            REPORT_FAILURE;
        }
        md_tag_t *new_tag = _create_tag(mem);
        if (NULL == new_tag) {
            REPORT_FAILURE;
        }
        new_tag->type = t;
        new_tag->length = l;
        new_tag->value = mem->alloc(l,mem->alloc_ctx);
        if (NULL == new_tag->value) {
            mem->dealloc(new_tag,mem->dealloc_ctx);
            REPORT_FAILURE;
        }
        medmemcpy(new_tag->value,*buffer,l);
        if (!consumeX((size_t)l,buffer,&block_length)) {
            freetag(mem,new_tag);
            new_tag = NULL;
            REPORT_FAILURE;
        }
        new_tag->next = *list_head;
        *list_head = new_tag;
    }

    return true;
}
/* -------------------------------------------------------------------------- */
static bool decode_producer_subblocks(med_mem_t const *mem,uint16_t block_type,
                    md_producer_t *prod, uint8_t const **buffer, size_t *remain)
{
    uint16_t pen_length;
    uint16_t block_length;

    DECODE_DBG("available bytes:%u",(unsigned int)*remain);

    switch (block_type) {
    case MED_SEC_TYPE:
        /* Can have only one security block and it has to precede any
           standard / vendor specific block */
        if (NULL != prod->token) {
            REPORT_FAILURE;
        }
        if (NULL != prod->pens) {
            REPORT_FAILURE;
        }
        prod->token = _create_security(mem);
        if (NULL == prod->token) {
            REPORT_FAILURE;
        }
        if (!consume2(&prod->token->length,buffer,remain)) {
            REPORT_FAILURE;
        }
        DECODE_DBG("security payload length:%u",prod->token->length);
        if (!consume2(&prod->token->scheme,buffer,remain)) {
            REPORT_FAILURE;
        }
        DECODE_DBG("security scheme: 0x%04X",prod->token->scheme);
        if (0 != prod->token->length) {
            if (prod->token->length > *remain) {
                REPORT_FAILURE;
            }
            prod->token->payload = mem->alloc(prod->token->length,mem->alloc_ctx);
            if (NULL == prod->token->payload) {
                REPORT_FAILURE;
            }
            medmemcpy(prod->token->payload,*buffer,prod->token->length);
            if (!consumeX(prod->token->length,buffer,remain)) {
                REPORT_FAILURE;
            }
        }
        break;
    case MED_VND_TYPE:
        if (!consume2(&pen_length, buffer,remain)) {
            REPORT_FAILURE;
        }
        /* ASSERT(4 == pen_length) ??? */
        md_pen_t *new_pen = _create_pen(mem);
        if (NULL == new_pen) {
            REPORT_FAILURE;
        }
        new_pen->next = prod->pens;
        prod->pens = new_pen;
        if (!consume4(&new_pen->id, buffer, remain)) {
            REPORT_FAILURE;
        }
        break;
    case MED_UP_TYPE: /* FALLTHRU */
    case MED_DN_TYPE:
        if (!consume2(&block_length,buffer,remain)) {
            REPORT_FAILURE;
        }
        if (block_length > *remain) {
            REPORT_FAILURE;
        }
        if (NULL == prod->pens) {
            prod->pens = _create_pen(mem);
            if (NULL == prod->pens) {
                REPORT_FAILURE;
            }
            prod->pens->id = 0; /* STANDARD, not VENDOR specific */
        }
        if (!_decode_tlvs(mem,
                         (MED_DN_TYPE == block_type) ? 
                          &prod->pens->downstream :
                          &prod->pens->upstream,
                          buffer,block_length)) {
            REPORT_FAILURE;
        }
        break;
    default:
        return false;
    }
    if (0 != *remain) {
        uint16_t next_block_type;
        if (!consume2(&next_block_type,buffer,remain)) {
            REPORT_FAILURE;
        }
        return decode_producer_subblocks(mem,next_block_type,prod,buffer,remain);
    }
    return true;
}
/* -------------------------------------------------------------------------- */
static md_producer_t *_create_new_producer(med_mem_t const *mem)
{
    md_producer_t *prod = mem->alloc(sizeof(md_producer_t),mem->alloc_ctx);
    if (NULL != prod) {
        medmemset(prod, 0, sizeof(md_producer_t));
    }
    return prod;
}
/* -------------------------------------------------------------------------- */
static bool decode_producer_block(med_mem_t const *mem,md_producer_t**prod,
                                        uint8_t const**buffer, size_t *remain)
{
    md_producer_t *new_producer = NULL;
    uint16_t block_type;
    uint16_t producer_length;
    DECODE_DBG("remain = %u",(unsigned int)*remain);
    if (!consume2(&block_type,buffer,remain)) {
        REPORT_FAILURE;
    }
    /* This producer block may be the first one, in which case it can be the
       default endpoint producer, in which case the buffer starts with either
       a security block, or a downstream block, or an upstream block, or a
       vendor section marker. Otherwise, we must have a producer section
       marker. */
    switch (block_type) {
    case MED_SEC_TYPE:
    case MED_VND_TYPE: /* FALLTHRU */
    case MED_DN_TYPE:  /* FALLTHRU */
    case MED_UP_TYPE:  /* FALLTHRU */
        DECODE_DBG("found an endpoint producer");
        /* Ok, we must be the first producer, an endpoint. Let's check we
           don't have any other producers */
        if (NULL != *prod) {
            REPORT_FAILURE;
        }
        new_producer = _create_new_producer(mem);
        if (NULL == new_producer) {
            REPORT_FAILURE;
        }
        new_producer->type = 0; /* ENDPOINT */
        break;
    case MED_PROD_TYPE:
        DECODE_DBG("found a non-endpoint producer");
        new_producer = _create_new_producer(mem);
        if (NULL == new_producer) {
            REPORT_FAILURE;
        }
        new_producer->type = MED_PROD_TYPE;
        if (!consume2(&producer_length, buffer, remain)) {
            freeprod(mem,new_producer);
            REPORT_FAILURE;
        }
        /* ASSERT(4 == producer_length) */
        if (producer_length > *remain) {
            freeprod(mem,new_producer);
            REPORT_FAILURE;
        }
        if (!consume4(&new_producer->precedence,buffer,remain)) {
            freeprod(mem,new_producer);
            REPORT_FAILURE;
        }
        break;
    default:
        REPORT_FAILURE;
    }
    if (!decode_producer_subblocks(mem,block_type,new_producer, buffer, remain)) {
        freeprod(mem,new_producer);
        REPORT_FAILURE;
    }
    new_producer->next = *prod;
    *prod = new_producer;
    return true;
}
/* -------------------------------------------------------------------------- */
static void freesec(med_mem_t const *mem,md_sec_t *sec)
{
    if (NULL != sec->payload) {
        mem->dealloc(sec->payload,mem->dealloc_ctx);
        sec->payload = NULL;
    }
    medmemset(sec,0xA5,sizeof(*sec));
    mem->dealloc(sec,mem->dealloc_ctx);
}
/* -------------------------------------------------------------------------- */
static void freepen(med_mem_t const *mem,md_pen_t *pen)
{
    md_pen_t *next = pen->next;
    if (NULL != pen->upstream) {
        freetag(mem,pen->upstream);
        pen->upstream = NULL;
    }
    if (NULL != pen->downstream) {
        freetag(mem,pen->downstream);
        pen->downstream = NULL;
    }
    medmemset(pen,0xA5,sizeof(*pen));
    mem->dealloc(pen,mem->dealloc_ctx);
    if (NULL != next) {
        freepen(mem,next);
    }
}
/* -------------------------------------------------------------------------- */
void freeprod(med_mem_t const *mem,md_producer_t *prod)
{
    md_producer_t *next = prod->next;
    if (NULL != prod->token) {
        freesec(mem,prod->token);
        prod->token = NULL;
    }
    if (NULL != prod->pens) {
        freepen(mem,prod->pens);
        prod->pens = NULL;
    }
    medmemset(prod,0xA5,sizeof(*prod));
    mem->dealloc(prod,mem->dealloc_ctx);
    if (NULL != next) {
        freeprod(mem,next);
    }
}
/* -------------------------------------------------------------------------- */
med_err_t med_decode_producers(const uint8_t*const buf,
                                 size_t* len,
                                 md_producer_t** prod,
                                 med_mem_t const* mem)
{
    med_err_t retcode = MED_OK;

    if (NULL == buf || NULL == len || NULL == prod) {
        return MED_BAD;
    }

    med_mem_t _mem;
    if (NULL != mem) {
        _mem = *mem;
    } else {
        _mem.alloc_ctx = NULL;
        _mem.dealloc_ctx = NULL;
        _mem.alloc = _malloc;
        _mem.dealloc = _dealloc;
    }

    md_producer_t *head_producer = NULL;

    const size_t buffer_length = *len;
    size_t remain = buffer_length;
    const uint8_t *data = buf;
    uint8_t version;

    if (!consume1(&version,&data,&remain)) {
        *len = buffer_length - remain;
        return MED_BAD;
    }

    while (0 != remain) {
        if (!decode_producer_block(&_mem,&head_producer, &data, &remain)) {
            *len = buffer_length - remain;
            retcode = MED_BAD;
            break;
        }
    }

    /* If something went wrong, clean-up */
    if (MED_OK != retcode && NULL != head_producer) {
        freeprod(mem,head_producer);
        head_producer = NULL;
    }

    *prod = head_producer;

    return retcode;
}