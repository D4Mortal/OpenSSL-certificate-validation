/*
 *
 * program written by Daniel Hao, May 2018
 *
 * Built on sample code provided by Dr. Chris Culnane
 *
 * Modifications by Sunday, May 2018
 * Daniel Hao, 834496
 */
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define MAX_URL_LENGTH 2083
#define MAX_FILENAME_LENGTH 255
#define RSA_KEY_LENGTH 2048
#define TLS_WEB_AUTH "TLS Web Server Authentication"

/* ************************************************************** */

/* function prototypes */

char *wild_card_CN(char* URL);

int verify_time(X509 *cert);

int verify_subject_alternitive_name(X509 *cert, char *URL);

int verify_common_name(X509 *cert, char *URL);

int verify_domain_name(X509 *cert, char *URL);

char *wild_card_CN(char* URL);

int verify_basic_constraint(X509 *cert);

int verify_Enhanced_Key_Usage(X509 *cert);

int verify_rsa_key_length(X509 *cert);

int verify_certificate(X509 *cert, char *URL);

void write_result(FILE *fp, char *filename, char *URL, int result);

/*****************************************************************************/

/* Verify the valid dates in the certificate
*/
int verify_time(X509 *cert){

    ASN1_TIME *not_before, *not_after;
    int pday, psec;
    not_before = X509_get_notBefore(cert);
    not_after = X509_get_notAfter(cert);

    ASN1_TIME_diff(&pday, &psec,not_before, NULL);
    if (pday < 0 || psec < 0){
        printf("The certificate is not yet valid\n");
        return 0;
    }
    ASN1_TIME_diff(&pday, &psec,NULL, not_after);
    if (pday < 0 || psec < 0){
        printf("The certificate has already expired\n");
        return 0;
    }

    return 1;
}

/*****************************************************************************/

/* Look for the url in certificate's subject alternitive name field
*/
int verify_subject_alternitive_name(X509 *cert, char *URL){
    GENERAL_NAMES *sub_alt_names;
    GENERAL_NAME *sub_alt_n;
    char *wild_URL = wild_card_CN(URL);
    unsigned char *alternitive_name;
    int num_of_altN, i;

    if((sub_alt_names = X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL))){
        num_of_altN = sk_GENERAL_NAME_num(sub_alt_names);

        for(i = 0; i < num_of_altN; i++){
            sub_alt_n = sk_GENERAL_NAME_value(sub_alt_names, i);

            if(sub_alt_n->type == GEN_DNS) {
                ASN1_STRING_to_UTF8(&alternitive_name, sub_alt_n->d.dNSName);

                if (strcasecmp(URL, (const char*)alternitive_name) == 0){
                    printf("Successfully found url in SAN\n");

                    free(wild_URL);
                    OPENSSL_free(alternitive_name);
                    sk_GENERAL_NAME_pop_free(sub_alt_names, GENERAL_NAME_free);
                    return 1;
                }
                if (strcasecmp(wild_URL, (const char*)alternitive_name) == 0){
                    printf("Successfully found url in SAN wildcard\n");

                    free(wild_URL);
                    OPENSSL_free(alternitive_name);
                    sk_GENERAL_NAME_pop_free(sub_alt_names, GENERAL_NAME_free);
                    return 1;
                }
                OPENSSL_free(alternitive_name);
            }
        }
    }

    sk_GENERAL_NAME_pop_free(sub_alt_names, GENERAL_NAME_free);
    free(wild_URL);
    printf("Failed to find matching subject alternitive name\n");
    return 0;
}

/*****************************************************************************/

/* Look for the url in certificate's comman name field
*/
int verify_common_name(X509 *cert, char *URL){
    X509_NAME *cert_subject = NULL;
    char subject_cn[MAX_URL_LENGTH];
    char *wild_URL = wild_card_CN(URL);

    cert_subject = X509_get_subject_name(cert);
    X509_NAME_get_text_by_NID(cert_subject, NID_commonName,
                                subject_cn, MAX_URL_LENGTH);

    if (strcasecmp(URL, subject_cn) == 0){
        printf("Successfully found common name\n");
        free(wild_URL);
        return 1;
    }
    if (strcasecmp(wild_URL, subject_cn) == 0){
        printf("Successfully found common name wildcard\n");
        free(wild_URL);
        return 1;
    }
    printf("Common name not found\n");
    free(wild_URL);
    return 0;
}

/*****************************************************************************/

/* Verify the certificate's domain name by first looking into subject
 * field, if it doesn't exist, then look into common name field
*/
int verify_domain_name(X509 *cert, char *URL){

    // check for subject alternitive names first
    if (verify_subject_alternitive_name(cert, URL)){
        return 1;
    }

    // if url is not in SAN, check for common name field
    else if (verify_common_name(cert, URL)){
        return 1;
    }

    printf("Does not contain domain name\n");
    return 0;
}

/*****************************************************************************/

/* Strip the url string and convert it into a wildcard entry for wildcard checks
*/
char *wild_card_CN(char* URL){
    char *wild_URL;
    int i = 0, index = 2;
    int copy = 0;

    wild_URL = malloc(sizeof(char) * strlen(URL));
    memset(wild_URL, 0, strlen(URL));
    wild_URL[0] = '*';
    wild_URL[1] = '.';

    // look for the first "." and copy everything after that
    for (i = 0; i < strlen(URL); i++){
        if (copy == 1){
            wild_URL[index] = URL[i];
            index++;
        }
        if (URL[i] == '.'){
            copy = 1;
        }
    }

    wild_URL[index] = '\0';
    return wild_URL;
}

/*****************************************************************************/

/* Verify if the ceritificate has CA:False or not
*/
int verify_basic_constraint(X509 *cert){
    BASIC_CONSTRAINTS *bc;
    if ((bc = X509_get_ext_d2i(cert, NID_basic_constraints, NULL, NULL))) {
        if (!bc->ca){ // if the CA flag is set to False, the certificate is valid
            BASIC_CONSTRAINTS_free(bc);
            return 1;
        }
    }
    BASIC_CONSTRAINTS_free(bc);
    printf("CA is not False\n");
    return 0;
}

/*****************************************************************************/

/* Verify if the certificate contains TSL Server Validation
*/
int verify_Enhanced_Key_Usage(X509 *cert){

    BUF_MEM *bptr = NULL;
    char *buffer;
    X509_EXTENSION *extended_key;
    BIO *bio;

    extended_key = X509_get_ext(cert,
                    X509_get_ext_by_NID(cert, NID_ext_key_usage, -1));

    bio = BIO_new(BIO_s_mem());
    if (!X509V3_EXT_print(bio, extended_key, 0, 0))
    {
        fprintf(stderr, "Error in reading extensions");
    }

    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bptr);

    //bptr->data is not NULL terminated - add null character
    buffer = malloc((bptr->length + 1) * sizeof(char));
    memset(buffer, 0, bptr->length + 1);
    memcpy(buffer, bptr->data, bptr->length);
    buffer[bptr->length] = '\0';

    // look for the TLS Server Authentication substring
    if(strstr(buffer, TLS_WEB_AUTH) != NULL) {
        BIO_free_all(bio);
        free(buffer);
        return 1;
    }

    printf("Extended key usage does not contain TLS Web Authentication\n");
    BIO_free_all(bio);
    free(buffer);
    return 0;

}

/*****************************************************************************/

/* Verify that the certificate's RSA key is atleast 2048
*/
int verify_rsa_key_length(X509 *cert){
    EVP_PKEY * public_key;
    RSA *rsa_key;
    int bit_length;

    public_key = X509_get_pubkey(cert);
    rsa_key = EVP_PKEY_get1_RSA(public_key);
    bit_length = RSA_size(rsa_key) * 8; //converting byte to bit

    if (bit_length >= RSA_KEY_LENGTH){
        RSA_free(rsa_key);
        EVP_PKEY_free(public_key);
        return 1;
    }

    printf("RSA key unsecure\n");
    RSA_free(rsa_key);
    EVP_PKEY_free(public_key);
    return 0;
}

/*****************************************************************************/

/* Use helper functions to validate the entire certificate
*/
int verify_certificate(X509 *cert, char *URL){

    if (verify_time(cert) && verify_domain_name(cert, URL) &&
        verify_rsa_key_length(cert) && verify_basic_constraint(cert) &&
        verify_Enhanced_Key_Usage(cert)){

            printf("Successfully validated the certificate!!\n");
            return 1;
        }
    printf("Failed to validate certificate\n");
    return 0;
}

/*****************************************************************************/

/* format results to csv
*/
void write_result(FILE *fp, char *filename, char *URL, int result){
    fprintf(fp, "%s,%s,%d\n", filename, URL, result);
}

/*****************************************************************************/

int main(int argc, char** argv){

    char *path = argv[1];
    char *cert_buffer, *url_buffer;
    char line_buffer[MAX_URL_LENGTH + MAX_FILENAME_LENGTH];
    BIO *certificate_bio = NULL;
    X509 *cert = NULL;
    FILE *fp, *output;

    //initialise openSSL
    OpenSSL_add_all_algorithms();
    ERR_load_BIO_strings();
    ERR_load_crypto_strings();

    // Open specified file for reading
    fp = fopen(path, "r");
    if (fp == NULL){
        fprintf(stderr, "Error in opening file\n\n");
        exit(EXIT_FAILURE);
    }
    else{
        fprintf(stderr, "Successfully opened file\n\n");
    }

    // Opening file for writing output
    output = fopen("output.csv", "w");
    if (output == NULL){
        fprintf(stderr, "Error in creating output file\n\n");
        exit(EXIT_FAILURE);
    }
    else{
        fprintf(stderr, "Successfully created output file\n\n");
    }

    memset(line_buffer, 0, MAX_URL_LENGTH + MAX_FILENAME_LENGTH);

    // loop through the input csv file to retrieve url and crt file
    while (fgets(line_buffer,sizeof(line_buffer), fp) != NULL) {

        //create BIO object to read certificate
        certificate_bio = BIO_new(BIO_s_file());

        cert_buffer = strtok(line_buffer, ",");
        url_buffer = strtok(NULL, "\n");

        //Read certificate into BIO
        if (!(BIO_read_filename(certificate_bio, cert_buffer)))
        {
            fprintf(stderr, "Error in reading cert BIO filename");
            exit(EXIT_FAILURE);
        }

        if (!(cert = PEM_read_bio_X509(certificate_bio, NULL, 0, NULL)))
        {
            fprintf(stderr, "Error in loading certificate");
            exit(EXIT_FAILURE);
        }

        write_result(output, cert_buffer, url_buffer,
                    verify_certificate(cert, url_buffer));

        memset(cert_buffer, 0, MAX_FILENAME_LENGTH);
        memset(url_buffer, 0, MAX_URL_LENGTH);
        memset(line_buffer, 0, MAX_URL_LENGTH + MAX_FILENAME_LENGTH);

        X509_free(cert);
        BIO_free_all(certificate_bio);
    }

    fclose(fp);
    fclose(output);
    exit(0);
}
