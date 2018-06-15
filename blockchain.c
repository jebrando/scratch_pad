#include <stdlib.h> 
#include <stdint.h> 
#include <string.h>
#include <time.h>

#include "blockchain.h"
#include "sha_algorithms.h"

typedef struct BLOCKCHAIN_BLOCK_TAG
{
    uint64_t index;
    time_t timestamp;
    hash_value_t proof_hash;
    hash_value_t prev_node_hash;
    unsigned char* transaction;
    size_t trans_length;
} BLOCKCHAIN_BLOCK;

typedef struct BLOCKCHAIN_NODE_TAG
{
    BLOCKCHAIN_BLOCK* data;
    struct BLOCKCHAIN_NODE_TAG* next;
} BLOCKCHAIN_NODE;

typedef struct BLOCKCHAIN_INFO_TAG
{
    proof_algorithm algorithm;
    BLOCKCHAIN_NODE* block_list;
    BLOCKCHAIN_NODE* block_tail;
} BLOCKCHAIN_INFO;

static hash_value_t default_proof_algorithm(hash_value_t last_proof)
{
    hash_value_t result = last_proof;
    do
    {
        result += 1;
    } while (result > last_proof);
    return result;
}

static hash_value_t calculate_hash(BLOCKCHAIN_BLOCK* block)
{
    hash_value_t result;
    SHA_CTX_HANDLE handle = sha_init(SHA_TYPE_256);
    if (handle == NULL)
    {
        result = 0;
    }
    else
    {
        size_t block_len = sizeof(BLOCKCHAIN_BLOCK);
        uint8_t msg_digest[SHA256_HASH_SIZE];
        if (sha_process(handle, (const uint8_t*)block, block_len, msg_digest, SHA256_HASH_SIZE) != 0)
        {
            result = 0;
        }
        else
        {
            result = 0;
        }

        sha_deinit(handle);
    }
    return 123456;
}

static int add_node(BLOCKCHAIN_INFO* chain_info, BLOCKCHAIN_BLOCK* block)
{
    int result;
    BLOCKCHAIN_NODE* node;
    if ((node = (BLOCKCHAIN_NODE*)malloc(sizeof(BLOCKCHAIN_BLOCK))) == NULL)
    {
        result = __LINE__;
    }
    else
    {
        node->data = block;
        node->next = NULL;
        chain_info->block_tail->next = node;
        chain_info->block_tail = node;
        result = 0;
    }
    return result;
}

BLOCKCHAIN_HANDLE blockchain_create(proof_algorithm algorithm)
{
    BLOCKCHAIN_INFO* result;
    BLOCKCHAIN_BLOCK* home_block;
    BLOCKCHAIN_NODE* node;
    if ((result = (BLOCKCHAIN_INFO*)malloc(sizeof(BLOCKCHAIN_INFO))) == NULL)
    {
        result = NULL;
    }
    else if ((home_block = (BLOCKCHAIN_BLOCK*)malloc(sizeof(BLOCKCHAIN_BLOCK))) == NULL)
    {
        free(result);
        result = NULL;
    }
    else if ((node = (BLOCKCHAIN_NODE*)malloc(sizeof(BLOCKCHAIN_NODE))) == NULL)
    {
        free(home_block);
        free(result);
        result = NULL;
    }
    else
    {
        memset(result, 0, sizeof(BLOCKCHAIN_INFO));
        if (algorithm == NULL)
        {
            result->algorithm = default_proof_algorithm;
        }
        else
        {
            result->algorithm = algorithm;
        }

        // Create the header block
        memset(home_block, 0, sizeof(BLOCKCHAIN_BLOCK));
        home_block->index = 1;
        node->data = home_block;
        node->next = NULL;
        result->block_list = result->block_tail = node;
    }
    return result;
}

void blockchain_destroy(BLOCKCHAIN_HANDLE handle)
{
    if (handle != NULL)
    {
        do
        {
            BLOCKCHAIN_NODE* tmp_block = handle->block_list;
            handle->block_list = handle->block_list->next;
            free(tmp_block->data->transaction);
            free(tmp_block->data);
            free(tmp_block);
        } while (handle->block_list != NULL);
        
        free(handle);
    }
}

BLOCKCHAIN_HANDLE blockchain_import(const char* json_block)
{
    return NULL;
}

char* blockchain_export(BLOCKCHAIN_HANDLE handle)
{
    char* result;
    if (handle == NULL)
    {
        result = NULL;
    }
    return result;
}

int add_block(BLOCKCHAIN_HANDLE handle, const unsigned char* transaction, size_t trans_len)
{
    int result;
    if (handle == NULL || transaction == NULL || trans_len == 0)
    {
        result = __LINE__;
    }
    else
    {
        BLOCKCHAIN_INFO* chain_info = (BLOCKCHAIN_INFO*)handle;
        BLOCKCHAIN_BLOCK* block;
        if ((block = (BLOCKCHAIN_BLOCK*)malloc(sizeof(BLOCKCHAIN_BLOCK))) == NULL)
        {
            result = __LINE__;
        }
        else if ((block->transaction = (unsigned char*)malloc(trans_len)) == NULL)
        {
            free(block);
            result = __LINE__;
        }
        else
        {
            block->index = chain_info->block_tail->data->index + 1;
            memcpy(block->transaction, transaction, trans_len);
            block->trans_length = trans_len;
            block->prev_node_hash = chain_info->block_tail->data->proof_hash;
            block->timestamp = time(NULL);
            block->proof_hash = calculate_hash(block);

            if (add_node(chain_info, block) != 0)
            {
                free(block->transaction);
                free(block);
                result = __LINE__;
            }
            else
            {
                result = 0;
            }
        }
    }
    return 0;
}
