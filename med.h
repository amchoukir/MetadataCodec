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

#ifndef __MED_H__
#define __MED_H__

#include <stdint.h>
#include <stddef.h>

struct md_enc_;
typedef struct md_enc_ md_enc_t;


typedef enum med_err_ {
    MED_OK,     /**< Sucess*/
    MED_MEM,    /**< Not enough space*/
    MED_BAD     /**< Improper arguments supplied*/
}med_err_t;


#define MED_IS_OK(err) ((err) == MED_OK)
#define MED_IS_ERROR(err) (!MED_IS_OK(err))

/** allocator
 *
 * Allocator can be malloc or another allocation function
 * when malloc is not to be used.
 *
 * @param[in] size number of bytes to allocate
 *
 * @return pointer to the allocated memory or NULL if no more memory.
 */
typedef void* (*allocator) (size_t size, void* ctx);

/** deallocator
 *
 * Deallocator can be free or another deallocation function
 * when malloc is not to be used.
 *
 * @param[in] size number of bytes to allocate
 *
 * @return pointer to the allocated memory or NULL if no more memory.
 */
typedef void (*deallocator) (void* ptr, void* ctx);

typedef struct med_mem_ {
    void* alloc_ctx;
    void* dealloc_ctx;
    allocator alloc;
    deallocator dealloc;
} med_mem_t;

/** med_init
 *
 *  Initialize a new encoding instance with its default state.
 *  The default state of the encoding instance is to allow the
 *  addition of standard tags for the endpoint in the upstream
 *  direction. The current state of the encoding instance can
 *  be altered using one of the med_set_XXX functions.
 *
 *  @param[in] enc encoding instance to initialize
 *  @param[in] mem memory allocation model
 *
 *  @return #med_err_t
 *
 *  @note an encoding instance can oly be initialized once. If
 *  you wish to go back to the default use #med_set_default
 *
 */
med_err_t med_init(md_enc_t* enc, med_mem_t* mem);

/** med_free
 *
 *  Free up any encoding internal resources allocated.
 *
 *  @param[in] enc encoding instance to free
 *
 *  @note It is the responsibility of the caller to free
 *  the md_enc_t data structure if dynamically allocated.
 *
 */
void med_free(md_enc_t* enc);

/** med_add_tok
 *
 *  Adds a security token to the encoding instance for
 *  its current state. See #med_init for default state.
 *
 *  @param[in] enc encoding instance
 *  @param[in] scheme securty scheme
 *  @param[in] length security payload length
 *  @param[in] payload security payload
 *
 *  @return #med_err_t
 *
 *  @note only one security scheme can be set per endpoint
 *  and per network producer precedence.
 */
med_err_t med_add_tok(md_enc_t* enc,
                         uint16_t scheme,
                         uint16_t length,
                         uint8_t* payload);

/** med_add_tag
 *
 *  Add a tag to the encoding instance for its current state.
 *  See #med_init for defualt state.
 *
 *  @param[in] enc encoding instance
 *  @param[in] type tag type
 *  @param[in] length tag length
 *  @param[in] value tag value
 *
 *  @return #med_err_t
 *
 *  @note a given tag can only be add once for any possible state.
 */
med_err_t med_add_tag(md_enc_t* enc,
                      uint16_t type,
                      uint16_t length,
                      uint8_t* value);

med_err_t med_set_default(md_enc_t* enc);
med_err_t med_set_ep(md_enc_t* enc);
med_err_t med_set_net(md_enc_t* enc, uint32_t precedence);
med_err_t med_set_std(md_enc_t* enc);
med_err_t med_set_vnd(md_enc_t* enc, uint32_t id);
med_err_t med_set_upstream(md_enc_t* enc);
med_err_t med_set_downstream(md_enc_t* enc);
/** med_is_ep
 *
 *  Is the encoding instance in endpoint state.
 *
 *  @param[in] enc ecoding instance
 *
 *  @return -1 for Invalid, 1 for TRUE, 0 for FALSE
 */
uint8_t  med_is_ep(md_enc_t* enc);

/** med_is_net
 *
 *  Is the encoding instance in network state.
 *
 *  @param[in] enc ecoding instance
 *
 *  @return -1 for Invalid, 1 for TRUE, 0 for FALSE
 */
uint8_t  med_is_net(md_enc_t* enc);

/** med_is_std
 *
 *  Is the encoding instance in standard state.
 *
 *  @param[in] enc ecoding instance
 *
 *  @return -1 for Invalid, 1 for TRUE, 0 for FALSE
 */
uint8_t  med_is_std(md_enc_t* enc);

/** med_is_vnd
 *
 *  Is the encoding instance in vendor state.
 *
 *  @param[in] enc ecoding instance
 *
 *  @return -1 for Invalid, 1 for TRUE, 0 for FALSE
 */
uint8_t  med_is_vnd(md_enc_t* enc);

/** med_is_up
 *
 *  Is the encoding instance in upstream state.
 *
 *  @param[in] enc ecoding instance
 *
 *  @return -1 for Invalid, 1 for TRUE, 0 for FALSE
 */
uint8_t  med_is_up(md_enc_t* enc);

/** med_is_dn
 *
 *  Is the encoding instance in downstream state.
 *
 *  @param[in] enc ecoding instance
 *
 *  @return -1 for Invalid, 1 for TRUE, 0 for FALSE
 */
uint8_t  med_is_dn(md_enc_t* enc);


/** med_encode
 *
 *  The function encode a set of metadata producers (prods) in the
 *  given buffer (buf).
 *
 *  @param[in] buf buffer to encode in 
 *  @param[in, out] len length of the buffer / encoded length
 *  @param[in] prods producer to encode
 *
 *  @return #med_err_t
 *
 *  @note in case of #MED_BAD error the len indicates where encoding stoped
 */
med_err_t med_encode(uint8_t* buf,
                     size_t* len,
                     md_enc_t* enc);


/** med_decode
 *
 *  The function decode a set of metadata producers (prods) fron the given
 *  buffer (buf)
 *
 *  @param[in] buf buffer to decode
 *  @param[in, out] len length of the buffer / decoded length
 *  @param[in] prods producer decoded
 *  @param[in] alloc allocator to be used for decoding
 *
 *  @return #med_err_t
 *
 *  @note in case of #MED_BAD error the len indicates where decoding stoped
 */
med_err_t med_decode(const uint8_t* buf,
                     size_t* len,
                     md_enc_t* enc,
                     med_mem_t mem);
/** med_sizeof
 *
 *  The function computes the size of the buffer needed to encode a given
 *  set of producers (prods)
 *
 *  @param[in] prods producer for which to compute the buffer size
 *  @param[out] len length of buffer needed to encode
 *
 *  @return #med_err_t
 *
 */
med_err_t med_sizeof(md_enc_t* enc,
                     size_t* len);

/* Walk related function and structs */
#include <stdbool.h>
typedef bool (*med_tlv_callback) (uint16_t type, uint16_t length,
                                                        void *value, void* ctx);
typedef bool (*med_upstream_callback) (void* ctx);
typedef bool (*med_downstream_callback) (void* ctx);
typedef bool (*med_vnd_callback) (uint32_t pen_value, void* ctx);
typedef bool (*med_token_callback) (uint16_t sec_len, uint16_t sec_scheme,
                                                void *sec_payload, void* ctx);
typedef bool (*med_prod_callback) (uint32_t precedence, void* ctx);
typedef bool (*med_preamble_callback) (void* ctx);

typedef struct {
    med_tlv_callback tlv;
    med_upstream_callback upstream;
    med_downstream_callback downstream;
    med_vnd_callback vnd;
    med_token_callback token;
    med_prod_callback prod;
    med_preamble_callback preamble;
} med_walk_callbacks_t;

med_err_t med_walk_public(md_enc_t *enc, med_walk_callbacks_t *cb,void *ctx);

#endif /* __MED_H__ */
