/*------------------------------------------------------------------
 * Encode/Decode Metadata Cross Protocol Encoding
 *
 *
 *------------------------------------------------------------------
 */

#ifndef __MED_H__
#define __MED_H__

#include <stdint.h>
#include <stddef.h>

struct md_enc_;
typedef struct md_enc_ md_enc_t;

#define MED_IS_OK(err) ((err) == 0)
#define MED_IS_ERROR(err) (!MED_IS_OK(err))

typedef enum med_err_ {
    MED_OK,     /**< Sucess*/
    MED_MEM,    /**< Not enough space*/
    MED_BAD     /**< Improper arguments supplied*/
}med_err_t;

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

#endif /* __MED_H__ */
