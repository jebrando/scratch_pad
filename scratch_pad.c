// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
#if WIN32
#include <vld.h>
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>
#include <inttypes.h>
#include <limits.h>

#include "azure_c_shared_utility/base64.h"
#include "azure_c_shared_utility/buffer_.h"
#include "azure_c_shared_utility/xlogging.h"
#include "blockchain.h"

#include "sha_algorithms.h"
#include "sha256_impl.h"

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
#define LENGTH_OF_VALIDITY  0x1E
#define TEMP_DATE_LENGTH    32
#define NOT_AFTER_OFFSET    15
#define TIME_FIELD_LENGTH   0x0D
#define END_HEADER_LENGTH   25

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
    ASN1_PRINTABLE_STRING = 0x13,
    ASN1_T61_STRING = 0x16,
    ASN1_UTCTIME = 0x17,
    ASN1_GENERALIZED_STRING = 0x18,
    ASN1_SEQUENCE = 0x30,
    ASN1_SET = 0x31,
    ASN1_INVALID
} ASN1_TYPE;

typedef enum TIME_POS_TYPE_TAG
{
    TIME_TYPE_YEAR = 1,
    TIME_TYPE_MONTH = 3,
    TIME_TYPE_DAY = 5,
    TIME_TYPE_HOUR = 7,
    TIME_TYPE_MIN = 9,
    TIME_TYPE_SEC = 11
} TIME_POS_TYPE;

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

typedef struct CERT_INFO_TAG
{
    char* certificate_pem;
    uint32_t version;
    uint32_t* serial_num;
    int signature;
    char issure_name[256];
    time_t not_before;
    time_t not_after;
    char* subject;
    const char* cert_chain;
} CERT_INFO;

typedef struct ASN1_OBJECT_TAG
{
    ASN1_TYPE type;
    uint32_t length;
    const unsigned char* value;
} ASN1_OBJECT;

// Construct the number of days of the start of each month
// exclude leap year (they are taken care of below)
static const int month_day[] = { 0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334 };

#define ASN1_MARKER         0x30
#define LENGTH_EXTENTION    0x82
#define ASN1_TYPE_INTEGER   0x02
#define EXTENDED_LEN_FLAG   0x80
#define LEN_FLAG_COUNT      0x7F
#define TLV_OVERHEAD_SIZE   0x2
#define LENGTH_OF_VALIDITY  0x1E
#define TEMP_DATE_LENGTH    32
#define NOT_AFTER_OFFSET    15
#define TIME_FIELD_LENGTH   0x0D
#define GENERAL_TIME_LENGTH 0x0F
#define END_HEADER_LENGTH   25
#define INVALID_TIME        -1

static const char* CERTIFICATE_PEM =
"-----BEGIN CERTIFICATE-----""\n"
"MIID1zCCAr+gAwIBAgIJALcEbK7ClhupMA0GCSqGSIb3DQEBCwUAMIGBMQswCQYDVQQGEwJVUzELMAkGA1UECAwCV0ExFDASBgNVBAcMC1dvb2RpbnZpbGxlMRIwEAYDVQQKDAlNaWNyb3NvZnQxDjAMBgNVBAsMBUF6dXJlMREwDwYDVQQDDAhqZWJyYW5kbzEYMBYGCSqGSIb3DQEJARYJamJAbXMuY29tMB4XDTE4MDQxNDA1NDUyMloXDTE4MDQyNDA1NDUyMlowgYExCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJXQTEUMBIGA1UEBwwLV29vZGludmlsbGUxEjAQBgNVBAoMCU1pY3Jvc29mdDEOMAwGA1UECwwFQXp1cmUxETAPBgNVBAMMCGplYnJhbmRvMRgwFgYJKoZIhvcNAQkBFglqYkBtcy5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCmHPz2KVQtDP0PfRv76suFR821mluRcTnvAqN5weU9LGL91J+0QQRw6faEexU0C86Ozo/P4KULCfrShRAeGvzJzyUZWau1wc4+oTkQfAIzOz4KOZpBf2imISfOysw0I3Exm9TNRVAmvapjY2mscRrUhE8H97jUnaGf0kxfW9VRdoT9CVPmjmK3P3SknChHFdcv9nSEJ98bNtklBH9JCCft/RcO+4zktD96khQ3srC78Cz8nNjZquK1OwK9p3x+BrukekgW+wAXhjvONNLgF2rbbCQCDYyZhUu6WAjM4II23/uA5Gie1xYQkRN0i779aA5FcS05fCBqNIyrCWtSqsG1AgMBAAGjUDBOMB0GA1UdDgQWBBSlTWvqdhHR818KM1PPJncyZYj5qjAfBgNVHSMEGDAWgBSlTWvqdhHR818KM1PPJncyZYj5qjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQCHjZaY9i/E33HUyV7RllZ5fFeUdrbmXK6xJE6xmvaWfnTRBVOHIMwhjxGRgINm0fqRzzugJrVK2zSoh1rbpTr4zYimB4qaShCYh3jRYS7IukrVfzy0dw/FdQOQ5q/4F3HqfK9wuk/6g3goUfAiVjuytucmUccO1K8iO2KI5jj3obEZyvvEdUr0c3yD8C7G/659v+fz07Kjoir4P1ZO2r3xj/G6yqtIYpPG1Z2RSkC5SrxeIQvfRUbvJuT7nkvUk2bxMlWli/x8rVFuJl7eR5T7MyfgUyLhjrzer1Vex7tVsn8aCKeO9Bb5qBd3DVQWpT20+NQSYVKblkSqrwxBteQZ""\n"
"-----END CERTIFICATE-----";
static const char* CERT_2_PEM = 
"-----BEGIN CERTIFICATE-----""\n"
"MIIBfTCCASSgAwIBAgIFGis8TV4wCgYIKoZIzj0EAwIwNDESMBAGA1UEAwwJcmlvdC1yb290MQswCQYDVQQGDAJVUzERMA8GA1UECgwITVNSX1RFU1QwHhcNMTcwMTAxMDAwMDAwWhcNMzcwMTAxMDAwMDAwWjA0MRIwEAYDVQQDDAlyaW90LXJvb3QxCzAJBgNVBAYMAlVTMREwDwYDVQQKDAhNU1JfVEVTVDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGmrWiahUg/J7F2llfSXSLn+0j0JxZ0fp1DTlEnI/Jzr3x5bsP2eRppj0jflBPvU+qJwT7EFnq2a1Tz4OWKxzn2jIzAhMAsGA1UdDwQEAwIABDASBgNVHRMBAf8ECDAGAQH/AgEBMAoGCCqGSM49BAMCA0cAMEQCIFFcPW6545a5BNP+yn9U/c0MwemXvzddylFa0KbDtANfAiB0rxBRLP1e7vZtzjJsLP6njjO6qWoArXRuTV2nDO3S9g==""\n"
"-----END CERTIFICATE-----";
static const char* TEST_RSA_CERT =
"-----BEGIN CERTIFICATE-----""\n"
"MIICpDCCAYwCCQCgAJQdOd6dNzANBgkqhkiG9w0BAQsFADAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwHhcNMTcwMTIwMTkyNTMzWhcNMjcwMTE4MTkyNTMzWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDlJ3fRNWm05BRAhgUY7cpzaxHZIORomZaOp2Uua5yv+psdkpv35ExLhKGrUIK1AJLZylnue0ohZfKPFTnoxMHOecnaaXZ9RA25M7XGQvw85ePlGOZKKf3zXw3Ds58GFY6Sr1SqtDopcDuMmDSg/afYVvGHDjb2Fc4hZFip350AADcmjH5SfWuxgptCY2Jl6ImJoOpxt+imWsJCJEmwZaXw+eZBb87e/9PH4DMXjIUFZebShowAfTh/sinfwRkaLVQ7uJI82Ka/icm6Hmr56j7U81gDaF0DhC03ds5lhN7nMp5aqaKeEJiSGdiyyHAescfxLO/SMunNc/eG7iAirY7BAgMBAAEwDQYJKoZIhvcNAQELBQADggEBACU7TRogb8sEbv+SGzxKSgWKKbw+FNgC4Zi6Fz59t+4jORZkoZ8W87NM946wvkIpxbLKuc4F+7nTGHHksyHIiGC3qPpi4vWpqVeNAP+kfQptFoWEOzxD7jQTWIcqYhvssKZGwDk06c/WtvVnhZOZW+zzJKXA7mbwJrfp8VekOnN5zPwrOCumDiRX7BnEtMjqFDgdMgs9ohR5aFsI7tsqp+dToLKaZqBLTvYwCgCJCxdg3QvMhVD8OxcEIFJtDEwm3h9WFFO3ocabCmcMDyXUL354yaZ7RphCBLd06XXdaUU/eV6fOjY6T5ka4ZRJcYDJtjxSG04XPtxswQfrPGGoFhk=""\n"
"-----END CERTIFICATE-----";
static const char* TEST_ECC_CERT =
"-----BEGIN CERTIFICATE-----""\n"
"MIIBfTCCASSgAwIBAgIFGis8TV4wCgYIKoZIzj0EAwIwNDESMBAGA1UEAwwJcmlvdC1yb290MQswCQYDVQQGDAJVUzERMA8GA1UECgwITVNSX1RFU1QwHhcNMTcwMTAxMDAwMDAwWhcNMzcwMTAxMDAwMDAwWjA0MRIwEAYDVQQDDAlyaW90LXJvb3QxCzAJBgNVBAYMAlVTMREwDwYDVQQKDAhNU1JfVEVTVDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABGmrWiahUg/J7F2llfSXSLn+0j0JxZ0fp1DTlEnI/Jzr3x5bsP2eRppj0jflBPvU+qJwT7EFnq2a1Tz4OWKxzn2jIzAhMAsGA1UdDwQEAwIABDASBgNVHRMBAf8ECDAGAQH/AgEBMAoGCCqGSM49BAMCA0cAMEQCIFFcPW6545a5BNP+yn9U/c0MwemXvzddylFa0KbDtANfAiB0rxBRLP1e7vZtzjJsLP6njjO6qWoArXRuTV2nDO3S9g==""\n"
"-----END CERTIFICATE-----";

#ifdef WIN32
static const char* CERT_AGENT_FILENAME = "G:\\certificates\\Edge\\edge-agent-ca\\edge-agent-ca.cert.pem";
static const char* CERT_CHAIN_FILENAME = "G:\\certificates\\Edge\\edge-chain-ca\\edge-chain-ca.cert.pem";
static const char* CERT_SERVER_FILENAME = "G:\\certificates\\Edge\\edge-hub-server\\edge-hub-server.cert.pem";
#else
static const char* CERT_AGENT_FILENAME = "/home/jebrando/development/scratch_pad/cert/signer_cert.cer";
static const char* CERT_CHAIN_FILENAME = "/home/jebrando/development/scratch_pad/cert/FullChain.cer";
static const char* CERT_SERVER_FILENAME = "G:\\certificates\\Edge\\edge-hub-server\\edge-hub-server.cert.pem";
#endif

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

static BUFFER_HANDLE decode_certificate(CERT_INFO* cert_info)
{
    BUFFER_HANDLE result;
    const char* iterator = cert_info->certificate_pem;
    char* cert_base64;
    size_t cert_idx = 0;

    // Allocate enough space for the certificate, 
    // no need to do append a +1 due to we're not
    // copying the headers
    size_t len = strlen(iterator);
    if ((cert_base64 = malloc(len)) == NULL)
    {
        LogError("Failure allocating base64 decoding certificate");
        result = NULL;
    }
    else
    {
        bool begin_hdr_end = false;
        int begin_hdr_len = 0;
        memset(cert_base64, 0, len);
        // If the cert does not begin with a '-' then
        // the certificate doesn't have a header
        if (*iterator != '-')
        {
            begin_hdr_end = true;
        }
        while (*iterator != '\0')
        {
            if (begin_hdr_end)
            {
                // Once we are in the header then, copy the cert excluding \r\n
                if (*iterator != '\r' && *iterator != '\n')
                {
                    cert_base64[cert_idx++] = *iterator;
                }
                if (*iterator == '\n' && *(iterator + 1) == '-')
                {
                    // Check to see if we have a chain embedded in the certificate
                    // if we've have more data after the END HEADER then we have a chain
                    if ((((iterator - cert_info->certificate_pem) + END_HEADER_LENGTH) + begin_hdr_len) < (int)len)
                    {
                        iterator++;
                        // Find the certificate chain here for later use
                        while (*iterator != '\0')
                        {
                            // check for end header
                            if (*iterator == '\n')
                            {
                                cert_info->cert_chain = iterator + 1;
                                break;
                            }
                            iterator++;
                        }
                    }

                    // If we encounter the \n- to signal the end header break out
                    break;
                }
            }
            else if (!begin_hdr_end && *iterator == '\n')
            {
                // Loop through the cert until we get to the \n at the end
                // of the header
                begin_hdr_end = true;
            }
            else
            {
                begin_hdr_len++;
            }
            iterator++;
        }
        result = Base64_Decoder(cert_base64);
        free(cert_base64);
    }
    return result;
}

static char* get_object_id_value(const ASN1_OBJECT* target_obj)
{
    // TODO: need to implement
    return NULL;
}

static time_t tm_to_utc(const struct tm *tm)
{
    // Most of the calculation is easy; leap years are the main difficulty.
    int month = tm->tm_mon % 12;
    int year = tm->tm_year + tm->tm_mon / 12;
    if (month < 0) // handle negative values (% 12 are still negative).
    {
        month += 12;
        --year;
    }

    // This is the number of Februaries since 1900.
    const int year_for_leap = (month > 1) ? year + 1 : year;

    // Construct the UTC value
    time_t result = tm->tm_sec                      // Seconds
        + 60 * (tm->tm_min                          // Minute = 60 seconds
            + 60 * (tm->tm_hour                         // Hour = 60 minutes
                + 24 * (month_day[month] + tm->tm_mday - 1  // Day = 24 hours
                    + 365 * (year - 70)                         // Year = 365 days
                    + (year_for_leap - 69) / 4                  // Every 4 years is     leap...
                    - (year_for_leap - 1) / 100                 // Except centuries...
                    + (year_for_leap + 299) / 400)));           // Except 400s.
    return result < 0 ? -1 : result;
}

static int is_time_type(TIME_POS_TYPE type, size_t index, uint8_t asn1_type)
{
    int result;
    size_t offset = 0;
    if (asn1_type == ASN1_GENERALIZED_STRING)
    {
        offset = 2;
    }
    if (index == (type + offset))
    {
        result = 0;
    }
    else
    {
        result = 1;
    }
    return result;
}

static time_t get_utctime_value(const unsigned char* time_value)
{
    time_t result;
    char temp_value[TEMP_DATE_LENGTH];
    size_t temp_idx = 0;
    struct tm target_time;
    uint32_t numeric_val;
    memset(&target_time, 0, sizeof(target_time));
    memset(temp_value, 0, TEMP_DATE_LENGTH);

    size_t time_length = *(time_value + 1);
    ASN1_TYPE current_type = *time_value;
    // Check the the type and the length
    if (current_type != ASN1_UTCTIME && current_type != ASN1_GENERALIZED_STRING)
    {
        LogError("Failure Invalid type specified for the time");
        result = 0;
    }
    else if (current_type == ASN1_UTCTIME && time_length != TIME_FIELD_LENGTH)
    {
        LogError("Failure Invalid length specified for length");
        result = 0;
    }
    else if (current_type == ASN1_GENERALIZED_STRING && time_length != GENERAL_TIME_LENGTH)
    {
        LogError("Failure Invalid length specified for length");
        result = 0;
    }
    else
    {
        TIME_POS_TYPE curr_time_pos = TIME_TYPE_YEAR;
        // Don't evaluate the Z at the end of the UTC time field
        for (size_t index = 0; index < time_length - 1; index++)
        {
            temp_value[temp_idx++] = time_value[index + 2];

            if (is_time_type(curr_time_pos, index, current_type) == 0)
            {
                switch (curr_time_pos)
                {
                case TIME_TYPE_YEAR:
                    numeric_val = atol(temp_value);
                    if (current_type == ASN1_UTCTIME)
                    {
                        numeric_val += 100;
                    }
                    target_time.tm_year = numeric_val;
                    memset(temp_value, 0, TEMP_DATE_LENGTH);
                    temp_idx = 0;
                    curr_time_pos = TIME_TYPE_MONTH;
                    break;
                case TIME_TYPE_MONTH:
                    numeric_val = atol(temp_value);
                    target_time.tm_mon = numeric_val - 1;
                    memset(temp_value, 0, TEMP_DATE_LENGTH);
                    temp_idx = 0;
                    curr_time_pos = TIME_TYPE_DAY;
                    break;
                case TIME_TYPE_DAY:
                    numeric_val = atol(temp_value);
                    target_time.tm_mday = numeric_val;
                    memset(temp_value, 0, TEMP_DATE_LENGTH);
                    temp_idx = 0;
                    curr_time_pos = TIME_TYPE_HOUR;
                    break;
                case TIME_TYPE_HOUR:
                    numeric_val = atol(temp_value);
                    target_time.tm_hour = numeric_val;
                    memset(temp_value, 0, TEMP_DATE_LENGTH);
                    temp_idx = 0;
                    curr_time_pos = TIME_TYPE_MIN;
                    break;
                case TIME_TYPE_MIN:
                    numeric_val = atol(temp_value);
                    target_time.tm_min = numeric_val;
                    memset(temp_value, 0, TEMP_DATE_LENGTH);
                    temp_idx = 0;
                    curr_time_pos = TIME_TYPE_SEC;
                    break;
                case TIME_TYPE_SEC:
                    numeric_val = atol(temp_value);
                    target_time.tm_sec = numeric_val;
                    memset(temp_value, 0, TEMP_DATE_LENGTH);
                    temp_idx = 0;
                    break;
                }
            }
        }
        result = tm_to_utc(&target_time);
    }
    return result;
}

static size_t calculate_size(const unsigned char* buff, size_t* pos_change)
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

static size_t parse_asn1_object(unsigned char* tbs_info, ASN1_OBJECT* asn1_obj)
{
    size_t idx = 0;
    size_t pos_change;
    // determine the type
    asn1_obj->type = tbs_info[idx++];
    asn1_obj->length = calculate_size(&tbs_info[idx], &pos_change);
    asn1_obj->value = &tbs_info[idx + pos_change];
    return pos_change;
}

static int parse_tbs_cert_info(unsigned char* tbs_info, size_t len, CERT_INFO* cert_info)
{
    int result = 0;
    int continue_loop = 0;
    size_t size_len;

    TBS_CERTIFICATE_FIELD tbs_field = FIELD_VERSION;
    unsigned char* iterator = tbs_info;
    ASN1_OBJECT target_obj;

    while ((iterator < tbs_info + len) && (result == 0) && (continue_loop == 0))
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

                    cert_info->version = target_obj.value[0];
                    iterator += 3;  // Increment past the array type
                    tbs_field = FIELD_SERIAL_NUM;
                }
                else
                {
                    LogError("Parse Error: Invalid version field");
                    result = __LINE__;
                }
            }
            else
            {
                // RFC 5280: Version is optional, assume version 1
                cert_info->version = 1;
                tbs_field = FIELD_SERIAL_NUM;
            }
            break;
        case FIELD_SERIAL_NUM:
            // OID
            parse_asn1_object(iterator, &target_obj);
            get_object_id_value(&target_obj);
            iterator += target_obj.length + TLV_OVERHEAD_SIZE; // Increment lenght plus type and length
            tbs_field = FIELD_SIGNATURE;
            break;
        case FIELD_SIGNATURE:
            parse_asn1_object(iterator, &target_obj);
            iterator += target_obj.length + TLV_OVERHEAD_SIZE;
            tbs_field = FIELD_ISSUER;   // Go to the next field
            break;
        case FIELD_ISSUER:
            size_len = parse_asn1_object(iterator, &target_obj);
            iterator += target_obj.length + TLV_OVERHEAD_SIZE + (size_len - 1); // adding len on issue due to the size being 
            tbs_field = FIELD_VALIDITY;   // Go to the next field
            break;
        case FIELD_VALIDITY:
            parse_asn1_object(iterator, &target_obj);
            if (target_obj.length != LENGTH_OF_VALIDITY)
            {
                result = __LINE__;
            }
            else
            {
                // Convert the ASN1 UTC format to a time
                if ((cert_info->not_before = get_utctime_value(target_obj.value)) == 0)
                {
                    result = __LINE__;
                }
                else if ((cert_info->not_after = get_utctime_value(target_obj.value + NOT_AFTER_OFFSET)) == 0)
                {
                    result = __LINE__;
                }
                else
                {
                    iterator += target_obj.length + TLV_OVERHEAD_SIZE;
                    tbs_field = FIELD_SUBJECT;   // Go to the next field
                }
            }
            break;
        case FIELD_SUBJECT:
            size_len = parse_asn1_object(iterator, &target_obj);
            iterator += target_obj.length + TLV_OVERHEAD_SIZE + (size_len - 1); // adding len on issue due to the size being 
            tbs_field = FIELD_VALIDITY;   // Go to the next field
            continue_loop = 1;
            break;
        case FIELD_SUBJECT_PUBLIC_KEY_INFO:
        case FIELD_ISSUER_UNIQUE_ID:
        case FIELD_SUBJECT_UNIQUE_ID:
        case FIELD_EXTENSIONS:
            break;
        }
    }
    return result;
}

static int parse_asn1_data(unsigned char* section, size_t len, X509_ASN1_STATE state, CERT_INFO* cert_info)
{
    int result = 0;
    for (size_t index = 0; index < len; index++)
    {
        if (section[index] == ASN1_MARKER)
        {
            index++;
            size_t offset;
            size_t section_size = calculate_size(&section[index], &offset);
            index += offset;
            result = parse_asn1_data(section + index, section_size, STATE_TBS_CERTIFICATE, cert_info);
            break;

        }
        else if (state == STATE_TBS_CERTIFICATE)
        {
            result = parse_tbs_cert_info(&section[index], len, cert_info);
            // Only parsing the TBS area of the certificate
            // Break here
            break;
        }
    }
    return result;
}

static int parse_certificate(CERT_INFO* cert_info)
{
    int result;
    BUFFER_HANDLE cert_bin = decode_certificate(cert_info);
    if (cert_bin == NULL)
    {
        LogError("Failure decoding certificate");
        result = __LINE__;
    }
    else
    {
        unsigned char* cert_buffer = BUFFER_u_char(cert_bin);
        size_t cert_buff_len = BUFFER_length(cert_bin);
        if (parse_asn1_data(cert_buffer, cert_buff_len, STATE_INITIAL, cert_info) != 0)
        {
            LogError("Failure parsing asn1 data field");
            result = __LINE__;
        }
        else
        {
            result = 0;
        }
        BUFFER_delete(cert_bin);
    }
    return result;
}

static int parse_certificate_file(const char* filename, CERT_INFO* cert_info)
{
    int result;
    cert_info->certificate_pem = open_certificate(filename);
    if (cert_info->certificate_pem == NULL)
    {
        result = __LINE__;
    }
    else
    {
        result = parse_certificate(cert_info);
        free(cert_info->certificate_pem);
    }
    return result;
}

typedef struct TRANSACTION_ITEMS_TAG
{
    int item1;
    int item2;
} TRANSACTION_ITEMS;

TRANSACTION_ITEMS trans_list[] = {
    { 1, 2 },
    { 3, 4 }
};

int main(void)
{
    int result = 0;
    CERT_INFO cert_info;
    memset(&cert_info, 0, sizeof(CERT_INFO));

    SHA_CTX_HANDLE sha_handle = sha_init(sha_256_get_interface());

    uint8_t msg_array[] = {'b', 'y', 'e'};
    size_t array_len = sizeof(msg_array)/sizeof(msg_array[0]);
    uint8_t msg_digest[SHA256_HASH_SIZE];
    size_t digest_len = SHA256_HASH_SIZE;
    sha_process(sha_handle, msg_array, array_len, msg_digest, digest_len);
    sha_deinit(sha_handle);


    //STRING_HANDLE strhandle = Base64_Encode_Bytes(msg_digest, digest_len);
    for (size_t index = 0; index < SHA256_HASH_SIZE; index++)
    {
        printf("%x", msg_digest[index]);
    }
    //printf("%s\r\n", STRING_c_str(strhandle));



    /*
    BLOCKCHAIN_HANDLE handle = blockchain_create(NULL);
    if (handle == NULL)
    {
        printf("blockchain create failed\r\n");
    }
    else
    {
        for (size_t index = 0; index < sizeof(trans_list)/sizeof(trans_list[0]); index++)
        {
            if (add_block(handle, (const unsigned char*)&trans_list[index], sizeof(trans_list[index])) != 0)
            {
                printf("Adding item %ud failed\r\n", index);
                break;
            }
        }
        blockchain_destroy(handle);
    }*/
    //result = parse_certificate_file(CERT_AGENT_FILENAME, &cert_info);
    //result = parse_certificate_file(CERT_CHAIN_FILENAME, &cert_info);

    //cert_info.certificate_pem = (char*)TEST_RSA_CERT;
    //result = parse_certificate(&cert_info);

    getchar();
    return result;
}
