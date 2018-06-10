// Copyright (c) Microsoft. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.
//#include <vld.h>

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/evp.h>

// Fatal error; abort with message, including file and line number
//
void fatal_error(const char *file, int line, const char *msg)
{
    fprintf(stderr, "**FATAL** %s:%i %s\n", file, line, msg);
    ERR_print_errors_fp(stderr);
}

#define print_error(msg) fatal_error(__FILE__, __LINE__, msg)

// Parameter settings for this cert
//
#define RSA_KEY_SIZE (1024)
#define ENTRIES     6
static const char* const REQ_FILE = "dps_csr.crt";
static const char* const KEY_FILE = "dps_csr.key";

// declare array of entries to assign to cert
struct entry
{
    char *key;
    char *value;
};

struct entry entries[ENTRIES] =
{
    { "countryName", "US" },
    { "stateOrProvinceName", "WA" },
    { "localityName", "Redmond" },
    { "organizationName", "microsoft.com" },
    { "organizationalUnitName", "Azure" },
    { "commonName", "dps_csr" },
};

static EVP_PKEY* create_evp_key(bool use_rsa_key)
{
    printf("Creating key pair...\r\n");
    EVP_PKEY* key;
    if (use_rsa_key)
    {
        BIGNUM* bne; 
        RSA* rsa_key;

        bne = BN_new();
        int ret_val = BN_set_word(bne, RSA_F4);

        rsa_key = RSA_new();
        if ((RSA_generate_key_ex(rsa_key, RSA_KEY_SIZE, bne, NULL)) != 1)
        {
            // Failure
            print_error("Could not generate RSA key\r\n");
            key = NULL;
        }
        // Create evp obj to hold our rsa_key
        else if (!(key = EVP_PKEY_new()))
        {
            key = NULL;
            print_error("Could not create EVP object\r\n");
        }
        else if (!(EVP_PKEY_set1_RSA(key, rsa_key)))
        {
            EVP_PKEY_free(key);
            key = NULL;
            print_error("Could not assign RSA key to EVP object");
        }
        RSA_free(rsa_key);
        BN_free(bne);
    }
    else
    {
        key = NULL;
    }
    return key;
}

static X509_REQ* create_request_object(EVP_PKEY* key)
{
    X509_REQ* result;
    X509_NAME* subj;

    if (!(result = X509_REQ_new()))
    {
        print_error("Failed to create X509_REQ object");
        result = NULL;
    }
    else if (!(subj = X509_NAME_new()))
    {
        print_error("Failed to create X509_NAME object");
        X509_REQ_free(result);
        result = NULL;
    }
    else
    {
        bool update_fail = false;
        X509_REQ_set_pubkey(result, key);
        // create and fill in subject object
        
        for (size_t index = 0; index < ENTRIES; index++)
        {
            int nid;                  // ASN numeric identifier
            X509_NAME_ENTRY *ent;

            if ((nid = OBJ_txt2nid(entries[index].key)) == NID_undef)
            {
                fprintf(stderr, "Error finding NID for %s\n", entries[index].key);
                update_fail = true;
                break;
            }
            if (!(ent = X509_NAME_ENTRY_create_by_NID(NULL, nid, MBSTRING_ASC, (unsigned char*)entries[index].value, - 1)))
            {
                printf("Error creating Name entry from NID");
                update_fail = true;
                break;
            }
            if (X509_NAME_add_entry(subj, ent, -1, 0) != 1)
            {
                printf("Error adding entry to Name");
                update_fail = true;
                break;
            }
        }

        if (update_fail || X509_REQ_set_subject_name(result, subj) != 1)
        {
            print_error("Error adding subject to request");
            X509_REQ_free(result);
            result = NULL;
        }
    }
    return result;
}

static int write_csr(X509_REQ* req, EVP_PKEY* key)
{
    int result;
    FILE *fp;
 
    // write output files
    if (!(fp = fopen(REQ_FILE, "w")))
    {
        printf("Error writing to request file");
        result = __LINE__;
    }
    else
    {
        if (PEM_write_X509_REQ(fp, req) != 1)
        {
            print_error("Error while writing request");
            result = __LINE__;
        }
        fclose(fp);

        if (!(fp = fopen(KEY_FILE, "w")))
        {
            printf("Error writing to private key file");
            result = __LINE__;
        }
        else
        {
            if (PEM_write_PrivateKey(fp, key, NULL, NULL, 0, 0, NULL) != 1)
            {
                print_error("Error while writing private key");
                result = __LINE__;
            }
            else
            {
                result = 0;
            }
            fclose(fp);
        }
    }
    return result;
}

int main(int argc, char *argv[])
{
    X509_REQ* req;

    // standard set up for OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // seed openssl's prng
    // commented out for now
    /*
    if (RAND_load_file("/dev/random", -1))
        print_error("Could not seed prng");
    */

    // Generate the RSA key; we don't assign a callback to monitor progress
    // since generating keys is fast enough these days
    EVP_PKEY* key = create_evp_key(true);
    if (key == NULL)
    {
        printf("Failure creating evp key\r\n");
    }
    else
    {
        // create request object
        req = create_request_object(key);
        if (req == NULL)
        {
            printf("Failed creating CSR object");
        }
        else
        {
            EVP_MD* digest;

            // request is filled in and contains our generated public key;
            // now sign it
            digest = (EVP_MD *)EVP_sha1();
            if (!(X509_REQ_sign(req, key, digest)))
            {
                print_error("Error signing request");
            }
            else
            {
                (void)write_csr(req, key);
            }
        }
        EVP_PKEY_free(key);
        X509_REQ_free(req);
    }
    return 0;
}
