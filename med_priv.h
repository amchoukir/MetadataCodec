/*------------------------------------------------------------------
 * Encode/Decode Metadata Cross Protocol Encoding
 *
 * @file
 *
 * @author Amine Choukir <amchouki@cisco.com>
 * @author Yann Poupet <ypoupet@cisco.com>
 *
 *------------------------------------------------------------------
 */
#ifndef __MED_PRIV_H__
#define __MED_PRIV_H__
#include "med.h"
#include <stdint.h>

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

/* Encoding structure types*/
#define MED_SEC_TYPE    0
#define MED_UP_TYPE     1
#define MED_DN_TYPE     2
#define MED_VND_TYPE    3
#define MED_NET_TYPE    4

typedef struct md_tag_ {
    uint16_t type;
    uint16_t length;
    uint8_t* value;
    struct md_tag_* next; /**< Last item should be NULL*/
} md_tag_t;

#define MED_PEN_STD 0
typedef struct md_pen_ {
    uint32_t   id;         /**< Private Enterprise Number assigned by IANA 
                                #MED_PEN_STD is standard*/
    md_tag_t* upstream;   /**< Upstream tags, NULL if none*/
    md_tag_t* downstream; /**< Downstream tags, NULL if none*/
    struct md_pen_* next;  /**< Last item should be NULL*/
} md_pen_t;

typedef struct md_sec_ {
    uint16_t scheme;    /**< Security method used*/
    uint16_t length;    /**< Payload length*/
    uint8_t* payload;   /**< Security scheme dependent payload*/
}md_sec_t;

#define MED_PROD_EP  0
#define MED_PROD_NET 1
typedef struct md_producer_ {
    uint16_t type;              /**< Endpoint: #MED_PROD_EP,
                                     Network: #MED_PROD_NET*/
    uint32_t precedence;        /**< Administrative precedence of this producer
                                 For endpoint this is not used*/
    md_sec_t* token;            /**< Security Token, NULL if none*/
    md_pen_t* pens;             /**< Standard and vendor specific tags*/
    struct md_producer_* next;  /**< Last item should be NULL*/
}md_producer_t;

struct md_enc_ {
    md_producer_t* prods;   /**< Producers encoding structures*/
    med_mem_t mem;          /**< Encoding instance memory model*/
    md_producer_t* prod;    /**< Current producer*/
    md_pen_t* pen;          /**< Current pen*/
    uint32_t precedence;     /**< Set producer precedence*/
    uint16_t type;           /**< Set producer type*/
    uint16_t dir;            /**< Set direction, #MED_UP_TYPE or #MED_DN_TYPE*/
    uint32_t id;             /**< Set PEN id, #MED_PEN_STD is standard*/
};

/* Encoding operation callbacks */
typedef med_err_t (*med_tlv_op) (md_tag_t* tag, void* ctx);
typedef med_err_t (*med_upstream_op) (md_tag_t* tags, void* ctx);
typedef med_err_t (*med_downstream_op) (md_tag_t* tags, void* ctx);
typedef med_err_t (*med_vnd_op) (md_pen_t* pen, void* ctx);
typedef med_err_t (*med_token_op) (md_sec_t* tok, void* ctx);
typedef med_err_t (*med_prod_op) (md_producer_t* prod, void* ctx);
typedef med_err_t (*med_preamble_op) (md_enc_t* enc, void* ctx);

typedef struct med_op_ {
    med_tlv_op tlv;
    med_upstream_op upstream;
    med_downstream_op downstream;
    med_vnd_op vnd;
    med_token_op token;
    med_prod_op prod;
    med_preamble_op preamble;
}med_op_t;


/*Big/Little Endian Macros */
#define PUTSHORT_BASE(b, s) uint16_t t_s = (uint16_t)(s);\
                            uint8_t* t_b = (uint8_t*)(b);\
                            *t_b++ = t_s >> 8;\
                            *t_b = t_s;\

#define PUTSHORT_MV(b, s) do {\
    PUTSHORT_BASE(b, s)\
    (b) += 2;\
} while(0)

#define PUTSHORT(b, s) do {\
    PUTSHORT_BASE(b, s)\
} while(0)

#define PUTLONG_BASE(b, s) uint32_t t_s = (uint32_t)(s);\
                           uint8_t* t_b = (uint8_t*)(b);\
                           *t_b++ = t_s >> 24;\
                           *t_b++ = t_s >> 16;\
                           *t_b++ = t_s >> 8;\
                           *t_b = t_s;\

#define PUTLONG_MV(b, s) do {\
    PUTLONG_BASE(b, s)\
    (b) += 4;\
} while(0)

#define PUTLONG(b, s) do {\
    PUTLONG_BASE(b, s)\
} while(0)

/* Utilities */
void* med_memcpy(void* dst, void* src, size_t len);
void med_dump_buf(const void* sp, size_t len);
int med_memcmp(const void* sp1, const void* sp2, size_t len);
void* med_memset(void *sp, int c, size_t len);

/* Decode */
med_err_t med_decode_producers(const uint8_t*const buf,
                                 size_t* len,
                                 md_producer_t** prod,
                                 med_mem_t const* mem);

med_err_t med_validate(md_enc_t* enc);

#endif /* __MED_PRIV_H__ */

