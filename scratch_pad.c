// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "azure_c_shared_utility/base64.h"
#include "azure_c_shared_utility/buffer_.h"

// Reference https://msdn.microsoft.com/en-us/library/windows/desktop/bb540796(v=vs.85).aspx
/*
The ASN.1 definition of an X.509 Certificate as defined by RFC 2459 looks like this

Certificate ::= SEQUENCE {
tbsCertificate      TBSCertificate,
signatureAlgorithm  AlgorithmIdentifier,
signature           BIT STRING
}
An X.509 Certificate is simply a signed TBSCertificate.

The definition of a TBSCertificate looks like this

TBSCertificate ::= SEQUENCE {
version                [0] EXPLICIT Version DEFAULT v1(0),
serialNumber               CertificateSerialNumber,
signature                  AlgorithmIdentifier,
issuer                     Name,
validity                   Validity,
subject                    Name,
subjectPublicKeyInfo       SubjectPublicKeyInfo,
issuerUniqueId         [1] IMPLICIT UniqueIdentifier OPTIONAL,
-- If present, version shall be v2 or v3
subjectUniqueId        [2] IMPLICIT UniqueIdentifier OPTIONAL,
-- If present, version shall be v2 or v3
extensions             [3] EXPLICIT Extensions OPTIONAL
-- If present, version shall be v3
}
*/

#define ASN1_MARKER         0x30
#define LENGTH_EXTENTION    0x82
#define ASN1_INDEX_         0xA0 // ??? is this A1, A2, A3

#define ASN1_TYPE_INTEGER   0x02

#define EXTENDED_LEN_FLAG   0x80
#define LEN_FLAG_COUNT      0x7F
#define TLV_OVERHEAD_SIZE   0x2

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
    ASN1_BIT_STRING = 0x3,
    ASN1_OCTET_STRING = 0x4,
    ASN1_NULL = 0x5,
    ASN1_OBJECT_ID = 0x6,
    ASN1_UTF8_STRING = 0xC,
    //ASN1_SET = 0x11,
    //ASN1_NUMERICAL_STRING = 0x13,
    ASN1_PRINTABLE_STRING = 0x13,
    ASN1_T61_STRING = 0x16,
    ASN1_UTCTIME = 0x17,
    ASN1_GENERALIZED_STRING = 0x18,
    ASN1_SEQUENCE = 0x30,
    ASN1_SET = 0x31,
    ASN1_INVALID
} ASN1_TYPE;

typedef enum TBS_CERTIFICATE_FIELD_TAG
{
    FIELD_VERSION,
    FIELD_SERIAL_NUM,
    FIELD_SIGNATURE,
    FIELD_ISSUER,
    FIELD_VALIDITY,
    FIELD_SUBJECT,
    FIELD_SUBJECT_PUBLIC_KEY_INFO,
    FIELD_ISSUER_UNIQUE_ID,
    FIELD_SUBJECT_UNIQUE_ID,
    FIELD_EXTENSIONS
} TBS_CERTIFICATE_FIELD;

typedef struct TBS_CERT_INFO_TAG
{
    uint32_t version;
    uint32_t* serial_num;
    int signature;
    char issure_name[256];
    time_t not_before;
    time_t not_after;
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

static const char* CERTIFICATE_PEM =
"-----BEGIN CERTIFICATE-----""\n"
"MIID1zCCAr+gAwIBAgIJALcEbK7ClhupMA0GCSqGSIb3DQEBCwUAMIGBMQswCQYD""\n"
"VQQGEwJVUzELMAkGA1UECAwCV0ExFDASBgNVBAcMC1dvb2RpbnZpbGxlMRIwEAYD""\n"
"VQQKDAlNaWNyb3NvZnQxDjAMBgNVBAsMBUF6dXJlMREwDwYDVQQDDAhqZWJyYW5k""\n"
"bzEYMBYGCSqGSIb3DQEJARYJamJAbXMuY29tMB4XDTE4MDQxNDA1NDUyMloXDTE4""\n"
"MDQyNDA1NDUyMlowgYExCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTEUMBIGA1UE""\n"
"BwwLV29vZGludmlsbGUxEjAQBgNVBAoMCU1pY3Jvc29mdDEOMAwGA1UECwwFQXp1""\n"
"cmUxETAPBgNVBAMMCGplYnJhbmRvMRgwFgYJKoZIhvcNAQkBFglqYkBtcy5jb20w""\n"
"ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmHPz2KVQtDP0PfRv76suF""\n"
"R821mluRcTnvAqN5weU9LGL91J+0QQRw6faEexU0C86Ozo/P4KULCfrShRAeGvzJ""\n"
"zyUZWau1wc4+oTkQfAIzOz4KOZpBf2imISfOysw0I3Exm9TNRVAmvapjY2mscRrU""\n"
"hE8H97jUnaGf0kxfW9VRdoT9CVPmjmK3P3SknChHFdcv9nSEJ98bNtklBH9JCCft""\n"
"/RcO+4zktD96khQ3srC78Cz8nNjZquK1OwK9p3x+BrukekgW+wAXhjvONNLgF2rb""\n"
"bCQCDYyZhUu6WAjM4II23/uA5Gie1xYQkRN0i779aA5FcS05fCBqNIyrCWtSqsG1""\n"
"AgMBAAGjUDBOMB0GA1UdDgQWBBSlTWvqdhHR818KM1PPJncyZYj5qjAfBgNVHSME""\n"
"GDAWgBSlTWvqdhHR818KM1PPJncyZYj5qjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3""\n"
"DQEBCwUAA4IBAQCHjZaY9i/E33HUyV7RllZ5fFeUdrbmXK6xJE6xmvaWfnTRBVOH""\n"
"IMwhjxGRgINm0fqRzzugJrVK2zSoh1rbpTr4zYimB4qaShCYh3jRYS7IukrVfzy0""\n"
"dw/FdQOQ5q/4F3HqfK9wuk/6g3goUfAiVjuytucmUccO1K8iO2KI5jj3obEZyvvE""\n"
"dUr0c3yD8C7G/659v+fz07Kjoir4P1ZO2r3xj/G6yqtIYpPG1Z2RSkC5SrxeIQvf""\n"
"RUbvJuT7nkvUk2bxMlWli/x8rVFuJl7eR5T7MyfgUyLhjrzer1Vex7tVsn8aCKeO""\n"
"9Bb5qBd3DVQWpT20+NQSYVKblkSqrwxBteQZ""\n"
"-----END CERTIFICATE-----";

#ifdef WIN32
    //static const char* TARGET_CERT = "G:\\Enlistment\\scratch_pad\\cert\\rsa_cert.pem";
    //static const char* BINARY_DATA = "./cert/rsa_cert.bin";
#else
    //static const char* TARGET_CERT = "./cert/rsa_cert.pem";
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

static char* get_object_id_value(ASN1_OBJECT target_obj)
{
    // TODO: need to implement
    return NULL;
}

static BUFFER_HANDLE decode_cert(char* cert_pem)
{
    // Go through the cert header and remove the ----- XXXX -----
    const char* begin_header = cert_pem;
    while (begin_header != NULL && *begin_header != '\n')
    {
        begin_header++;
    }
    begin_header++;

    char* end_header = (char*)begin_header;
    // Loop through till we find a \n followed by -
    while (*end_header != '\0' && end_header+1 != NULL)
    {
        if (*end_header == '\n' && *(end_header+1) == '-')
        {
            *end_header = '\0';
            break;
        }
        end_header++;
    }

    /*size_t length = strlen(cert_pem);
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
    }*/
    BUFFER_HANDLE result = Base64_Decoder(begin_header);

    return result;
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

static void parse_asn1_object(unsigned char* tbs_info, ASN1_OBJECT* asn1_obj)
{
    size_t idx = 0;
    size_t pos_change;
    // determine the type
    asn1_obj->type = tbs_info[idx++];
    asn1_obj->length = calculate_size(&tbs_info[idx], &pos_change);
    asn1_obj->value = &tbs_info[idx + pos_change];
}

static int parse_tbs_cert_info(unsigned char* tbs_info, size_t len, TBS_CERT_INFO* tbs_cert_info)
{
    int result = 0;
    int continue_loop = 0;
    size_t curr_idx = 0;

    TBS_CERTIFICATE_FIELD tbs_field = FIELD_VERSION;
    unsigned char* iterator = tbs_info;
    ASN1_OBJECT target_obj;

    while ((iterator < tbs_info+len) && (result == 0) && (continue_loop == 0) )
    {
        switch (tbs_field)
        {
            case FIELD_VERSION:
                // Version field
                if (*iterator == 0xA0) // Array type
                {
                    iterator++;
                    if (*iterator == 0x03) // Length of this array
                    {
                        iterator++;
                        parse_asn1_object(iterator, &target_obj);
                        // Validate version
                        uint32_t temp;
                        memcpy(&temp, target_obj.value, sizeof(uint32_t));
                        (void)temp;

                        tbs_cert_info->version = target_obj.value[0];
                        iterator += 3;  // Increment past the array type
                        tbs_field = FIELD_SERIAL_NUM;
                    }
                    else
                    {
                        result = __LINE__;
                    }
                }
                else
                {
                    result = __LINE__;
                }
                break;
            case FIELD_SERIAL_NUM:
                // OID
                parse_asn1_object(iterator, &target_obj);
                get_object_id_value(target_obj);
                iterator += target_obj.length + TLV_OVERHEAD_SIZE; // Increment lenght plus type and length
                tbs_field = FIELD_SIGNATURE;
                break;
            case FIELD_SIGNATURE:
                parse_asn1_object(iterator, &target_obj);
                iterator += target_obj.length + TLV_OVERHEAD_SIZE;
                tbs_field = FIELD_ISSUER;   // Go to the next field
                break;
            case FIELD_ISSUER:
                parse_asn1_object(iterator, &target_obj);
                iterator += target_obj.length + TLV_OVERHEAD_SIZE;
                tbs_field = FIELD_VALIDITY;   // Go to the next field
            case FIELD_VALIDITY:
                parse_asn1_object(iterator, &target_obj);
                iterator += target_obj.length + TLV_OVERHEAD_SIZE;
                tbs_field = FIELD_SUBJECT;   // Go to the next field
                continue_loop = 1;
                break;
            case FIELD_SUBJECT:
            case FIELD_SUBJECT_PUBLIC_KEY_INFO:
            case FIELD_ISSUER_UNIQUE_ID:
            case FIELD_SUBJECT_UNIQUE_ID:
            case FIELD_EXTENSIONS:
                break;
        }
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

static int parse(const char* cert_pem)
{
    int result;
    BUFFER_HANDLE decoded_cert = decode_cert((char*)cert_pem);
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
    return result;
}

int main(void)
{
    int result;
    //result = parse_certificate(TARGET_CERT);
    result = parse(CERTIFICATE_PEM);
    return result;
}
