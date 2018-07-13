
#ifndef SHA_ALGORITHM_H
#define SHA_ALGORITHM_H

#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#include <cstdlib> 
#include <cstdint>
#else
#include <stdlib.h> 
#include <stdint.h>
#endif

    typedef void* SHA_IMPL_HANDLE;
    typedef struct SHA_CTX_TAG* SHA_CTX_HANDLE;

    typedef SHA_IMPL_HANDLE(*initialize_hash)(void);
    typedef void(*deinitialize_hash)(SHA_IMPL_HANDLE handle);
    typedef int(*process_hash)(SHA_IMPL_HANDLE handle, const uint8_t* msg_array, size_t array_len);
    typedef int(*retrieve_hash_result)(SHA_IMPL_HANDLE handle, uint8_t msg_digest[], size_t digest_len);

    typedef struct SHA_HASH_INTERFACE_TAG
    {
        initialize_hash Initialize_Hash;
        deinitialize_hash Deinitialize_Hash;
        process_hash Process_Hash;
        retrieve_hash_result Retrieve_Hash_Result;
    } SHA_HASH_INTERFACE;

    extern SHA_CTX_HANDLE sha_init(const SHA_HASH_INTERFACE* hash_interface);
    extern int sha_process(SHA_CTX_HANDLE handle, const uint8_t* msg_array, size_t array_len, uint8_t msg_digest[], size_t digest_len);
    extern void sha_deinit(SHA_CTX_HANDLE handle);

#ifdef __cplusplus
}
#endif

#endif /* SHA_ALGORITHM_H */
