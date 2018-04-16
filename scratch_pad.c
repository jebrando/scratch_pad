// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "azure_c_shared_utility/base64.h"
#include "azure_c_shared_utility/buffer_.h"

// Reference https://msdn.microsoft.com/en-us/library/windows/desktop/bb540796(v=vs.85).aspx

#define ASN1_MARKER         0x30
#define LENGTH_EXTENTION    0x82
#define ASN1_INDEX_         0xA0 // ??? is this A1, A2, A3

#define ASN1_TYPE_INTEGER   0x02

#define EXTENDED_LEN_FLAG   0x80
#define LEN_FLAG_COUNT      0x7F

typedef enum X509_ASN1_STATE_TAG
{
    STATE_INITIAL,
    STATE_TBS_CERTIFICATE,
    STATE_SIGNATURE_ALGO,
    STATE_SIGNATURE_VALUE
} X509_ASN1_STATE;

typedef enum ASN1_TYPE_TAG
{
    ASN1_BOOLEAN = 0x1,
    ASN1_INTEGER = 0x2,
    ASN1_BIT_STRING = 0X3,
    ASN1_NULL = 0X5,
    ASN1_OBJECT_ID = 0X6,
    ASN1_UTF8_STRING = 0XC
} ASN1_TYPE;

typedef struct TBS_CERT_INFO_TAG
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
} TBS_CERT_INFO;

typedef struct ASN1_OBJECT_TAG
{
    ASN1_TYPE type;
    uint32_t length;
    const unsigned char* value;
} ASN1_OBJECT;

#ifdef WIN32
    static const char* TARGET_CERT = "C:\\Enlistment\\scratch_pad\\cert\\rsa_cert.pem";
    //static const char* BINARY_DATA = "./cert/rsa_cert.bin";
#else
static const char* TARGET_CERT = "./cert/rsa_cert.pem";
//static const char* BINARY_DATA = "./cert/rsa_cert.bin";
#endif

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

static BUFFER_HANDLE decode_cert(char* cert_pem)
{
    // Go through the cert and remove the begin and end tags
    size_t length = strlen(cert_pem);
    int delimit_count = 0;
    for (size_t index = length-1; index > 0; index--)
    {
        if (cert_pem[index] != '-' && cert_pem[index] != '\n' && cert_pem[index] != '\r')
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

static size_t calculate_size(unsigned char* buff, size_t* pos_change)
{
    // TODO: Read spec to see the max size field
    size_t result;
    if ((buff[0] & EXTENDED_LEN_FLAG))
    {
        // We are using more than 128 bits, let see how many
        size_t num_bits = buff[0] & LEN_FLAG_COUNT;
        result = 0;
        for (size_t idx = 0; idx < num_bits; idx++)
        {
            unsigned char temp = buff[idx+1];
            if (idx == 0)
            {
                result = temp;
            }
            else
            {
                result = (result << 8)+temp;
            }
        }
        *pos_change = num_bits+1;
    }
    else
    {
        // The buffer is the size
        result = buff[0];
        *pos_change = 1;
    }
    return result;
}

static int parse_asn1_object(unsigned char* tbs_info, ASN1_OBJECT* asn1_obj)
{
    int result = 0;
    // determine the type
    switch (tbs_info[0])
    {
        case 0x2:
            asn1_obj->type = ASN1_INTEGER;
            break;
        default:
            result = __LINE__;
            break;
    }
    if (result == 0)
    {
        asn1_obj->length = tbs_info[1];
        asn1_obj->value = &tbs_info[2];
    }
    return result;
}

static int parse_tbs_cert_info(unsigned char* tbs_info, size_t len, TBS_CERT_INFO* tbs_cert_info)
{
    int result;
    size_t curr_idx = 0;
    // Figure out version
    if (tbs_info[curr_idx] == 0xA0)
    {
        curr_idx++;
        if (tbs_info[curr_idx] == 0x3) // Length
        {
            ASN1_OBJECT ver_obj;
            curr_idx++;
            parse_asn1_object(&tbs_info[curr_idx], &ver_obj);
            // Validate version
            memcpy(tbs_cert_info->version, ver_obj.value, sizeof(uint32_t));
        }
    }
    else
    {
        result = __LINE__;
    }
    return result;
}

static size_t parse_asn1_data(unsigned char* section, size_t len, X509_ASN1_STATE state, TBS_CERT_INFO* tbs_cert_info)
{
    size_t result = 0;
    for (size_t index = 0; index < len; index++)
    {
        if (section[index] == ASN1_MARKER)
        {
            index++;
            size_t offset;
            size_t section_size = calculate_size(&section[index], &offset);
            index += offset;
            parse_asn1_data(section+index, section_size, STATE_TBS_CERTIFICATE, tbs_cert_info);

        }
        else if (state == STATE_TBS_CERTIFICATE)
        {
            result = parse_tbs_cert_info(&section[index], len, tbs_cert_info);
        }
    }
    return result;
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
        // Free the certificate data
        free(certificate);
        if (decoded_cert == NULL)
        {
            result = __LINE__;
        }
        else
        {
            unsigned char* cert_buffer = BUFFER_u_char(decoded_cert);
            size_t cert_buff_len = BUFFER_length(decoded_cert);
            // Read 
            TBS_CERT_INFO tbs_cert_info;
            parse_asn1_data(cert_buffer, cert_buff_len, STATE_INITIAL, &tbs_cert_info);

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
