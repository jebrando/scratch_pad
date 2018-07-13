#include <stdlib.h>
#include <stdio.h>
#include "sha_algorithms.h"

typedef struct SHA_CTX_TAG
{
    const SHA_HASH_INTERFACE* hash_interface;
    SHA_IMPL_HANDLE sha_impl_handle;
} SHA_CTX;

SHA_CTX_HANDLE sha_init(const SHA_HASH_INTERFACE* hash_interface)
{
    SHA_CTX* result;
    if (hash_interface == NULL)
    {
        result = NULL;
    }
    else if ((result = (SHA_CTX*)malloc(sizeof(SHA_CTX))) == NULL)
    {
    }
    else
    {
        result->hash_interface = hash_interface;
        if (result->hash_interface->Initialize_Hash == NULL ||
            result->hash_interface->Deinitialize_Hash == NULL ||
            result->hash_interface->Process_Hash == NULL ||
            result->hash_interface->Retrieve_Hash_Result == NULL)
        {
            free(result);
            result = NULL;
        }
        else
        {
            result->sha_impl_handle = result->hash_interface->Initialize_Hash();
        }
    }
    return result;
}

void sha_deinit(SHA_CTX_HANDLE handle)
{
    if (handle != NULL)
    {
        handle->hash_interface->Deinitialize_Hash(handle->sha_impl_handle);
        free(handle);
    }
}

int sha_process(SHA_CTX_HANDLE handle, const uint8_t* msg_array, size_t array_len, uint8_t msg_digest[], size_t digest_len)
{
    int result;
    if (handle == NULL || msg_array == NULL || array_len == 0 || msg_digest == 0)
    {
        result = __LINE__;
    }
    else
    {
        if (handle->hash_interface->Process_Hash(handle->sha_impl_handle, msg_array, array_len) != 0)
        {
            result = __LINE__;
        }
        else if (handle->hash_interface->Retrieve_Hash_Result(handle->sha_impl_handle, msg_digest, digest_len) != 0)
        {
            result = __LINE__;
        }
        else
        {
            result = 0;
        }
    }
    return result;
}
