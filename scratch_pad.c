// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "azure_c_shared_utility/base64.h"
#include "azure_c_shared_utility/buffer_.h"

typedef struct CERT_SEQUENCE_TAG
{
    uint32_t version;
    uint32_t serial_num;
    int signature;
    char issure_name[256];
    uint32_t validity;
    char subject;
    //subjectPublicKeyInfo spki;
    unsigned char issuerUniqueId[1]; // Optional
    //subjectUniqueID[2];
    //extensions[3];
} CERT_SEQUENCE;

static const char* TARGET_CERT = "./cert/rsa_cert.pem";
static const char* BINARY_DATA = "./cert/rsa_cert.bin";

static char* open_certificate(const char* filename)
{
    char* result;

    FILE* file_ptr = fopen(filename, "rb");
    if (file_ptr == NULL)
    {
        (void)printf("Failure opening cert: %s", filename);
        result = NULL;
    }
    else
    {
        fseek(file_ptr, 0, SEEK_END);
        long cert_len = ftell(file_ptr);
        if (cert_len <= 0)
        {
            (void)printf("Failure certificate is empty");
            result = NULL;
        }
        else if ((result = malloc(cert_len+1)) == NULL)
        {
            (void)printf("Failure allocating certificate memory");
        }
        else
        {
            memset(result, 0, cert_len+1);
            fseek(file_ptr, 0, SEEK_SET);
            size_t ret_len = fread(result, sizeof(char), cert_len, file_ptr);
            if (ret_len != cert_len)
            {
                (void)printf("Failure reading certificate");
                free(result);
                result = NULL;
            }
        }
        fclose(file_ptr);
    }
    return result;
}

static BUFFER_HANDLE decode_cert(char* cert_pem)
{
    // Go through the cert and remove the begin and end
    size_t length = strlen(cert_pem);
    int delimit_count = 0;
    for (size_t index = length-1; index > 0; index--)
    {
        if (cert_pem[index] != '-' && cert_pem[index] != '\n')
        {
            if (delimit_count == 0)
            {
                do {} while (cert_pem[index--] != '-');
            }
            else
            {
                cert_pem[index+1] = '\0';
                break;
            }
            delimit_count++;
        }
    }

    const char* decode_val = cert_pem;
    while (decode_val != NULL && *decode_val != '\n')
    {
        decode_val++;
    }
    decode_val++;

    return Base64_Decoder(decode_val);
}

static void save_data(const char* filename, const unsigned char* data, size_t length)
{
    FILE* file_ptr = fopen(filename, "wb");
    if (file_ptr == NULL)
    {
        (void)printf("Failure opening cert: %s", filename);
    }
    else
    {
        size_t ret_len = fwrite(data, sizeof(unsigned char), length, file_ptr);
        if (ret_len != length)
        {
            (void)printf("Failure reading certificate");
        }
        fclose(file_ptr);
    }
}

static int parse_certificate(const char* filename)
{
    int result;
    char* certificate = open_certificate(filename);
    if (certificate == NULL)
    {
        result = __LINE__;
    }
    else
    {
        BUFFER_HANDLE decoded_cert;

        decoded_cert = decode_cert(certificate);

        free(certificate);
        if (decoded_cert == NULL)
        {
            result = __LINE__;
        }
        else
        {
            //save_data(BINARY_DATA, BUFFER_u_char(decoded_cert), BUFFER_length(decoded_cert));
            BUFFER_delete(decoded_cert);
            result = 0;
        }
    }
    return result;
}

int main(void)
{
    int result;

    result = parse_certificate(TARGET_CERT);

    return result;
}
