
#ifndef BLOCKCHAIN_H
#define BLOCKCHAIN_H

typedef struct BLOCKCHAIN_INFO_TAG* BLOCKCHAIN_HANDLE;

#ifdef __cplusplus
extern "C"
{
#else
#endif
    typedef uint8_t hash_value_t;

    typedef hash_value_t (*proof_algorithm)(hash_value_t last_proof);

    extern BLOCKCHAIN_HANDLE blockchain_create(proof_algorithm algorithm);
    extern void blockchain_destroy(BLOCKCHAIN_HANDLE handle);

    extern BLOCKCHAIN_HANDLE blockchain_import(const char* json_block);
    extern char* blockchain_export(BLOCKCHAIN_HANDLE handle);

    extern int add_block(BLOCKCHAIN_HANDLE handle, const unsigned char* transaction, size_t trans_len);

    // Management functions

#ifdef __cplusplus
}
#endif

#endif /* BLOCKCHAIN_H */
