
#ifndef SHA256_ALGORITHM_H
#define SHA256_ALGORITHM_H

#ifdef __cplusplus
extern "C" {
#include <cstdlib> 
#else
#include <stdlib.h> 
#endif

    #include "sha_algorithms.h"

    #define SHA512_HASH_SIZE    64

    extern const SHA_HASH_INTERFACE* sha512_get_interface(void);

#ifdef __cplusplus
}
#endif

#endif /* SHA256_ALGORITHM_H */
