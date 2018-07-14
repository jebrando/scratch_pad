#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include "sha_algorithms.h"
#include "sha512_impl.h"

#define SHA_512_MSG_BLOCK_SIZE      1024

typedef struct SHA_CTX_512_TAG
{
    uint64_t intermediate_hash[SHA512_HASH_SIZE / 8]; /* Message Digest */
    uint64_t len_low, len_high;   /* Message length in bits */

    int_least16_t msg_block_index;  /* msg_block array index */
                                    /* 1024-bit message blocks */
    uint8_t msg_block[SHA_512_MSG_BLOCK_SIZE];
    int is_computed;                       /* Is the digest computed? */
    int is_corrupted;                      /* Is the digest corrupted? */
} SHA_CTX_512;

// Initial Hash Values: FIPS-180-2 section 5.3.2
static uint64_t SHA512_H0[] = {
    0x6A09E667F3BCC908ull, 0xBB67AE8584CAA73Bull, 0x3C6EF372FE94F82Bull,
    0xA54FF53A5F1D36F1ull, 0x510E527FADE682D1ull, 0x9B05688C2B3E6C1Full,
    0x1F83D9ABFB41BD6Bull, 0x5BE0CD19137E2179ull
};

/*
* These definitions are defined in FIPS-180-2, section 4.1.
* Ch() and Maj() are defined identically in sections 4.1.1,
* 4.1.2 and 4.1.3.
*
* The definitions used in FIPS-180-2 are as follows:
*/
#ifndef USE_MODIFIED_MACROS
#define SHA_Ch(x,y,z)        (((x) & (y)) ^ ((~(x)) & (z)))
#define SHA_Maj(x,y,z)       (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#else /* USE_MODIFIED_MACROS */
// The following definitions are equivalent and potentially faster.
#define SHA_Ch(x, y, z)      (((x) & ((y) ^ (z))) ^ (z))
#define SHA_Maj(x, y, z)     (((x) & ((y) | (z))) | ((y) & (z)))
#endif /* USE_MODIFIED_MACROS */

#define SHA_Parity(x, y, z)  ((x) ^ (y) ^ (z))

// add "length" to the length
#define SHA384_512AddLength(sha_ctx, length)                \
  (add_temp = (sha_ctx)->len_low, (sha_ctx)->is_corrupted = \
    (((sha_ctx)->len_low += (length)) < add_temp) &&        \
    (++(sha_ctx)->len_high == 0) ? 1 : 0)

/* Define the SHA shift, rotate left and rotate right macro */
#define SHA512_SHR(bits,word)      ((word) >> (bits))
#define SHA512_ROTL(bits,word)                         \
  (((word) << (bits)) | ((word) >> (64-(bits))))
#define SHA512_ROTR(bits,word)                         \
  (((word) >> (bits)) | ((word) << (64-(bits))))

/* Define the SHA SIGMA and sigma macros */
#define SHA512_SIGMA0(word)   \
  (SHA512_ROTR(28,word) ^ SHA512_ROTR(34,word) ^ SHA512_ROTR(39,word))
#define SHA512_SIGMA1(word)   \
  (SHA512_ROTR(14,word) ^ SHA512_ROTR(18,word) ^ SHA512_ROTR(41,word))
#define SHA512_sigma0(word)   \
  (SHA512_ROTR( 1,word) ^ SHA512_ROTR( 8,word) ^ SHA512_SHR( 7,word))
#define SHA512_sigma1(word)   \
  (SHA512_ROTR(19,word) ^ SHA512_ROTR(61,word) ^ SHA512_SHR( 6,word))

static void sha512_process_msg_block(SHA_CTX_512* sha_ctx)
{
    /* Constants defined in FIPS-180-2, section 4.2.2 */
    static const uint64_t K[80] = {
        0x428A2F98D728AE22ull, 0x7137449123EF65CDull, 0xB5C0FBCFEC4D3B2Full,
        0xE9B5DBA58189DBBCull, 0x3956C25BF348B538ull, 0x59F111F1B605D019ull,
        0x923F82A4AF194F9Bull, 0xAB1C5ED5DA6D8118ull, 0xD807AA98A3030242ull,
        0x12835B0145706FBEull, 0x243185BE4EE4B28Cull, 0x550C7DC3D5FFB4E2ull,
        0x72BE5D74F27B896Full, 0x80DEB1FE3B1696B1ull, 0x9BDC06A725C71235ull,
        0xC19BF174CF692694ull, 0xE49B69C19EF14AD2ull, 0xEFBE4786384F25E3ull,
        0x0FC19DC68B8CD5B5ull, 0x240CA1CC77AC9C65ull, 0x2DE92C6F592B0275ull,
        0x4A7484AA6EA6E483ull, 0x5CB0A9DCBD41FBD4ull, 0x76F988DA831153B5ull,
        0x983E5152EE66DFABull, 0xA831C66D2DB43210ull, 0xB00327C898FB213Full,
        0xBF597FC7BEEF0EE4ull, 0xC6E00BF33DA88FC2ull, 0xD5A79147930AA725ull,
        0x06CA6351E003826Full, 0x142929670A0E6E70ull, 0x27B70A8546D22FFCull,
        0x2E1B21385C26C926ull, 0x4D2C6DFC5AC42AEDull, 0x53380D139D95B3DFull,
        0x650A73548BAF63DEull, 0x766A0ABB3C77B2A8ull, 0x81C2C92E47EDAEE6ull,
        0x92722C851482353Bull, 0xA2BFE8A14CF10364ull, 0xA81A664BBC423001ull,
        0xC24B8B70D0F89791ull, 0xC76C51A30654BE30ull, 0xD192E819D6EF5218ull,
        0xD69906245565A910ull, 0xF40E35855771202Aull, 0x106AA07032BBD1B8ull,
        0x19A4C116B8D2D0C8ull, 0x1E376C085141AB53ull, 0x2748774CDF8EEB99ull,
        0x34B0BCB5E19B48A8ull, 0x391C0CB3C5C95A63ull, 0x4ED8AA4AE3418ACBull,
        0x5B9CCA4F7763E373ull, 0x682E6FF3D6B2B8A3ull, 0x748F82EE5DEFB2FCull,
        0x78A5636F43172F60ull, 0x84C87814A1F0AB72ull, 0x8CC702081A6439ECull,
        0x90BEFFFA23631E28ull, 0xA4506CEBDE82BDE9ull, 0xBEF9A3F7B2C67915ull,
        0xC67178F2E372532Bull, 0xCA273ECEEA26619Cull, 0xD186B8C721C0C207ull,
        0xEADA7DD6CDE0EB1Eull, 0xF57D4F7FEE6ED178ull, 0x06F067AA72176FBAull,
        0x0A637DC5A2C898A6ull, 0x113F9804BEF90DAEull, 0x1B710B35131C471Bull,
        0x28DB77F523047D84ull, 0x32CAAB7B40C72493ull, 0x3C9EBE0A15C9BEBCull,
        0x431D67C49C100D4Cull, 0x4CC5D4BECB3E42B6ull, 0x597F299CFC657E2Aull,
        0x5FCB6FAB3AD6FAECull, 0x6C44198C4A475817ull
    };
    int        t, t8;                   /* Loop counter */
    uint64_t temp1, temp2;            /* Temporary word value */
    uint64_t W[80];                   /* Word sequence */
    uint64_t A, B, C, D, E, F, G, H;  /* Word buffers */

    // Initialize the first 16 words in the array W
    for (t = t8 = 0; t < 16; t++, t8 += 8)
    {
        W[t] = (((uint64_t)sha_ctx->msg_block[t8]) << 56) |
            (((uint64_t)sha_ctx->msg_block[t8 + 1]) << 48) |
            (((uint64_t)sha_ctx->msg_block[t8 + 2]) << 40) |
            (((uint64_t)sha_ctx->msg_block[t8 + 3]) << 32) |
            (((uint64_t)sha_ctx->msg_block[t8 + 4]) << 24) |
            (((uint64_t)sha_ctx->msg_block[t8 + 5]) << 16) |
            (((uint64_t)sha_ctx->msg_block[t8 + 6]) << 8) |
            (((uint64_t)sha_ctx->msg_block[t8 + 7]));
    }

    for (t = 16; t < 80; t++)
    {
        W[t] = SHA512_SIGMA1(W[t - 2]) + W[t - 7] +
            SHA512_SIGMA0(W[t - 15]) + W[t - 16];
    }

    A = sha_ctx->intermediate_hash[0];
    B = sha_ctx->intermediate_hash[1];
    C = sha_ctx->intermediate_hash[2];
    D = sha_ctx->intermediate_hash[3];
    E = sha_ctx->intermediate_hash[4];
    F = sha_ctx->intermediate_hash[5];
    G = sha_ctx->intermediate_hash[6];
    H = sha_ctx->intermediate_hash[7];

    for (t = 0; t < 80; t++)
    {
        temp1 = H + SHA512_SIGMA1(E) + SHA_Ch(E, F, G) + K[t] + W[t];
        temp2 = SHA512_SIGMA0(A) + SHA_Maj(A, B, C);
        H = G;
        G = F;
        F = E;
        E = D + temp1;
        D = C;
        C = B;
        B = A;
        A = temp1 + temp2;
    }

    sha_ctx->intermediate_hash[0] += A;
    sha_ctx->intermediate_hash[1] += B;
    sha_ctx->intermediate_hash[2] += C;
    sha_ctx->intermediate_hash[3] += D;
    sha_ctx->intermediate_hash[4] += E;
    sha_ctx->intermediate_hash[5] += F;
    sha_ctx->intermediate_hash[6] += G;
    sha_ctx->intermediate_hash[7] += H;

    sha_ctx->msg_block_index = 0;
}

static void pad_512_msg(SHA_CTX_512* sha_ctx, unsigned char pad_byte)
{
    /*
    * Check to see if the current message block is too small to hold
    * the initial padding bits and length. If so, we will pad the
    * block, process it, and then continue padding into a second
    * block.
    */
    if (sha_ctx->msg_block_index >= (SHA_512_MSG_BLOCK_SIZE - 8))
    {
        sha_ctx->msg_block[sha_ctx->msg_block_index++] = pad_byte;
        while (sha_ctx->msg_block_index < SHA_512_MSG_BLOCK_SIZE)
        {
            sha_ctx->msg_block[sha_ctx->msg_block_index++] = 0;
        }
        sha512_process_msg_block(sha_ctx);
    }
    else
    {
        sha_ctx->msg_block[sha_ctx->msg_block_index++] = pad_byte;
    }

    while (sha_ctx->msg_block_index < (SHA_512_MSG_BLOCK_SIZE - 8))
    {
        sha_ctx->msg_block[sha_ctx->msg_block_index++] = 0;
    }

    // Store the message length as the last 8 octets
    sha_ctx->msg_block[56] = (uint8_t)(sha_ctx->len_high >> 24);
    sha_ctx->msg_block[57] = (uint8_t)(sha_ctx->len_high >> 16);
    sha_ctx->msg_block[58] = (uint8_t)(sha_ctx->len_high >> 8);
    sha_ctx->msg_block[59] = (uint8_t)(sha_ctx->len_high);
    sha_ctx->msg_block[60] = (uint8_t)(sha_ctx->len_low >> 24);
    sha_ctx->msg_block[61] = (uint8_t)(sha_ctx->len_low >> 16);
    sha_ctx->msg_block[62] = (uint8_t)(sha_ctx->len_low >> 8);
    sha_ctx->msg_block[63] = (uint8_t)(sha_ctx->len_low);

    sha512_process_msg_block(sha_ctx);
}

static int sha512_retrieve_result(SHA_IMPL_HANDLE sha_handle, uint8_t* msg_digest, size_t digest_len)
{
    int result;
    if (sha_handle == NULL || msg_digest == NULL || digest_len == 0)
    {
        result = __LINE__;
    }
    else
    {
        SHA_CTX_512* sha_ctx = (SHA_CTX_512*)sha_handle;
        if (sha_ctx->is_corrupted)
        {
            result = __LINE__;
        }
        else
        {
            if (!sha_ctx->is_computed)
            {
                //finalize_256_result(sha_ctx, 0x80);
                pad_512_msg(sha_ctx, 0x80);
                // message may be sensitive, so clear it out
                for (size_t index = 0; index < SHA_512_MSG_BLOCK_SIZE; ++index)
                {
                    sha_ctx->msg_block[index] = 0;
                }
                sha_ctx->len_low = 0;  /* and clear length */
                sha_ctx->len_high = 0;
                sha_ctx->is_computed = 1;
            }
            for (size_t index = 0; index < digest_len; index++)
            {
                msg_digest[index] = (uint8_t)(sha_ctx->intermediate_hash[index >> 2] >> 8 * (3 - (index & 0x03)));
            }
        }
    }
    return result;
}

static int sha512_process_hash(SHA_IMPL_HANDLE sha_handle, const uint8_t* msg_array, size_t array_len)
{
    int result;
    if (sha_handle == NULL || msg_array == NULL || array_len == 0)
    {
        result = __LINE__;
    }
    else
    {
        SHA_CTX_512* sha_ctx = (SHA_CTX_512*)sha_handle;
        if (sha_ctx->is_computed || sha_ctx->is_corrupted)
        {
            result = __LINE__;
        }
        else
        {
            uint64_t add_temp;

            while (array_len-- && !sha_ctx->is_corrupted)
            {
                sha_ctx->msg_block[sha_ctx->msg_block_index] = (*msg_array & 0xFF);
                if (!SHA384_512AddLength(sha_ctx, 8) && (sha_ctx->msg_block_index == SHA_512_MSG_BLOCK_SIZE))
                {
                    sha512_process_msg_block(sha_ctx);
                }
            }
        }
    }
    return result;
}

static SHA_IMPL_HANDLE sha512_initialize(void)
{
    SHA_CTX_512* result;
    if ((result = malloc(sizeof(SHA_CTX_512))) == NULL)
    {
    }
    else
    {
        memset(result, 0, sizeof(SHA_CTX_512));
        for (size_t index = 0; index < 8; index++)
        {
            result->intermediate_hash[index] = SHA512_H0[index];
        }
    }
    return result;
}

static void sha512_deinit(SHA_IMPL_HANDLE handle)
{
    if (handle != NULL)
    {
        free(handle);
    }
}

static SHA_HASH_INTERFACE sha_interface =
{
    sha512_initialize,
    sha512_deinit,
    sha512_process_hash,
    sha512_retrieve_result
};

const SHA_HASH_INTERFACE* sha512_get_interface(void)
{
    return &sha_interface;
}
