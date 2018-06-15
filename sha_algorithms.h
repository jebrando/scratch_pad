
#ifndef SHA_ALGORITHM_H
#define SHA_ALGORITHM_H

#ifdef __cplusplus
extern "C"
{
#include <cstdlib> 
#include <cstdint>
#else
#include <stdlib.h> 
#include <stdint.h>
#endif

    #define SHA256_HASH_SIZE    32
    #define SHA512_HASH_SIZE    64

    typedef struct SHA_CTX_TAG* SHA_CTX_HANDLE;

    typedef enum SHA_TYPE_TAG
    {
        SHA_TYPE_1,
        SHA_TYPE_256,
        SHA_TYPE_512,
    } SHA_TYPE;


    extern SHA_CTX_HANDLE sha_init(SHA_TYPE type);
    extern int sha_process(SHA_CTX_HANDLE handle, const uint8_t* msg_array, size_t array_len, uint8_t* msg_digest, size_t digest_len);
    extern void sha_deinit(SHA_CTX_HANDLE handle);

#ifdef __cplusplus
}
#endif

#endif /* SHA_ALGORITHM_H */
