#define _GNU_SOURCE
#include <stdio.h>
#include <stdbool.h>
#include "identity.h"
#include "identity-resolver.h"
#include "identity-openssl-bridge.h"
#include "picohttpparser.h"

/* Cipher suites, https://www.openssl.org/docs/apps/ciphers.html */
const char *const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!SRP:!PSK:!CAMELLIA:!RC4:!MD5:!DSS";
const char *const IDENTITY_ERROR_XML = "<context><name>Unknown</name><result xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"defaultResult\" message=\"Identity Service Failure : %d\">RESET</result></context>";

int verify_callback(int preverify, X509_STORE_CTX * x509_ctx);
void init_openssl_library(void);
char *create_query(StrMap * parameters);
void print_error_string(unsigned long err, const char *const label);
char *perform_read(BIO * web);
unsigned char *get_cn_name(const char *label, X509_NAME * const name);

bool endsWith(char *base, char *str)
{
    int blen = strlen(base);
    int slen = strlen(str);
    return (blen >= slen) && (0 == strcmp(base + blen - slen, str));
}

void ssl_initialize_identity_context(identity_context_t * identity_context, char *certificate_file_name, char *truststore_file_name, char *key_file_name, char *key_password)
{
    long res = 1;
    int ret = 1;
    unsigned long ssl_err = 0;

    SSL_CTX *ctx = NULL;

    /* Internal function that wraps the OpenSSL init's   */
    /* Cannot fail because no OpenSSL function fails ??? */
    init_openssl_library();

    /* https://www.openssl.org/docs/ssl/SSL_CTX_new.html */
    const SSL_METHOD *method = SSLv23_method();
    ssl_err = ERR_get_error();

    ASSERT(NULL != method);
    if (!(NULL != method)) {
        print_error_string(ssl_err, "SSLv23_method");
        //break; /* failed */
    }

    /* http://www.openssl.org/docs/ssl/ctx_new.html */
    ctx = SSL_CTX_new(method);
    /* ctx = SSL_CTX_new(TLSv1_method()); */
    ssl_err = ERR_get_error();

    ASSERT(ctx != NULL);
    if (!(ctx != NULL)) {
        print_error_string(ssl_err, "SSL_CTX_new");
        //break; /* failed */
    }

    /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, verify_callback);
    /* Cannot fail ??? */

    /* https://www.openssl.org/docs/ssl/ctx_set_verify.html */
    SSL_CTX_set_verify_depth(ctx, 5);
    /* Cannot fail ??? */

    /* Remove the most egregious. Because SSLv2 and SSLv3 have been      */
    /* removed, a TLSv1.0 handshake is used. The client accepts TLSv1.0  */
    /* and above. An added benefit of TLS 1.0 and above are TLS          */
    /* extensions like Server Name Indicatior (SNI).                     */
    const long flags = SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
    long old_opts = SSL_CTX_set_options(ctx, flags);
    UNUSED(old_opts);

    /* http://www.openssl.org/docs/ssl/SSL_CTX_load_verify_locations.html */
    //res = SSL_CTX_load_verify_locations(ctx, "random-org-chain.pem", NULL);
    res = SSL_CTX_load_verify_locations(ctx, (truststore_file_name != NULL) ? truststore_file_name : "truststore.pem", NULL);
    ssl_err = ERR_get_error();

    ASSERT(1 == res);
    if (!(1 == res)) {
        /* Non-fatal, but something else will probably break later */
        print_error_string(ssl_err, "SSL_CTX_load_verify_locations");
        /* break; */
    }

    res = SSL_CTX_use_certificate_file(ctx, certificate_file_name, SSL_FILETYPE_PEM);
    ssl_err = ERR_get_error();

    ASSERT(1 == res);
    if (!(1 == res)) {
        /* Non-fatal, but something else will probably break later */
        print_error_string(ssl_err, "SSL_CTX_use_certificate_file");
        /* break; */
    }
    //SSL_CTX_set_default_passwd_cb(ctx, &pem_passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (void *) key_password);
    res = SSL_CTX_use_RSAPrivateKey_file(ctx, (key_file_name != NULL) ? key_file_name : certificate_file_name, SSL_FILETYPE_PEM);
    ssl_err = ERR_get_error();

    ASSERT(1 == res);
    if (!(1 == res)) {
        /* Non-fatal, but something else will probably break later */
        print_error_string(ssl_err, "SSL_CTX_use_RSAPrivatekey_file");
        /* break; */
    }
    identity_context->ssl_ctx = ctx;
}

void ssl_free_identity_context(identity_context_t * identity_context)
{
    if (identity_context != NULL && identity_context->ssl_ctx != NULL)
        SSL_CTX_free(identity_context->ssl_ctx);
    /* OpenSSL cleanup */
    ENGINE_cleanup();
    CONF_modules_unload(1);
    EVP_cleanup();
    sk_free((_STACK *) SSL_COMP_get_compression_methods());
    CRYPTO_cleanup_all_ex_data();
    ERR_remove_thread_state(NULL);
    ERR_free_strings();
}

char *send_message(identity_context_t * identity_context, char *path, StrMap * parameters)
{
    long res = 1;
    int ret = 1;
    unsigned long ssl_err = 0;

    BIO *web = NULL, *out = NULL;
    SSL *ssl = NULL;

    web = BIO_new_ssl_connect(identity_context->ssl_ctx);
    ssl_err = ERR_get_error();

    ASSERT(web != NULL);
    if (!(web != NULL)) {
        print_error_string(ssl_err, "BIO_new_ssl_connect");
        //break; /* failed */
    }

    /* https://www.openssl.org/docs/crypto/BIO_s_connect.html */
    char hostname[256];
    sprintf(hostname, "%s:%d", get_host(), HOST_PORT);
    res = BIO_set_conn_hostname(web, hostname);
    ssl_err = ERR_get_error();

    ASSERT(1 == res);
    if (!(1 == res)) {
        print_error_string(ssl_err, "BIO_set_conn_hostname");
        //break; /* failed */
    }

    /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
    /* This copies an internal pointer. No need to free.  */
    BIO_get_ssl(web, &ssl);
    ssl_err = ERR_get_error();

    ASSERT(ssl != NULL);
    if (!(ssl != NULL)) {
        print_error_string(ssl_err, "BIO_get_ssl");
        //break; /* failed */
    }

    /* https://www.openssl.org/docs/ssl/ssl.html#DEALING_WITH_PROTOCOL_CONTEXTS */
    /* https://www.openssl.org/docs/ssl/SSL_CTX_set_cipher_list.html            */
    res = SSL_set_cipher_list(ssl, PREFERRED_CIPHERS);
    ssl_err = ERR_get_error();

    ASSERT(1 == res);
    if (!(1 == res)) {
        print_error_string(ssl_err, "SSL_set_cipher_list");
        //break; /* failed */
    }

    /* No documentation. See the source code for tls.h and s_client.c */
    res = SSL_set_tlsext_host_name(ssl, get_host());
    ssl_err = ERR_get_error();

    ASSERT(1 == res);
    if (!(1 == res)) {
        /* Non-fatal, but who knows what cert might be served by an SNI server  */
        /* (We know its the default site's cert in Apache and IIS...)           */
        print_error_string(ssl_err, "SSL_set_tlsext_host_name");
        /* break; */
    }

    /* https://www.openssl.org/docs/crypto/BIO_s_file.html */
    out = BIO_new_fp(stdout, BIO_NOCLOSE);
    ssl_err = ERR_get_error();

    ASSERT(NULL != out);
    if (!(NULL != out)) {
        print_error_string(ssl_err, "BIO_new_fp");
        //break; /* failed */
    }

    /* https://www.openssl.org/docs/crypto/BIO_s_connect.html */
    res = BIO_do_connect(web);
    ssl_err = ERR_get_error();

    ASSERT(1 == res);
    if (!(1 == res)) {
        print_error_string(ssl_err, "BIO_do_connect");
        //break; /* failed */
    }

    /* https://www.openssl.org/docs/crypto/BIO_f_ssl.html */
    res = BIO_do_handshake(web);
    ssl_err = ERR_get_error();

    ASSERT(1 == res);
    if (!(1 == res)) {
        print_error_string(ssl_err, "BIO_do_handshake");
        //break; /* failed */
    }

    /**************************************************************************************/
    /**************************************************************************************/
    /* You need to perform X509 verification here. There are two documents that provide   */
    /*   guidance on the gyrations. First is RFC 5280, and second is RFC 6125. Two other  */
    /*   documents of interest are:                                                       */
    /*     Baseline Certificate Requirements:                                             */
    /*       https://www.cabforum.org/Baseline_Requirements_V1_1_6.pdf                    */
    /*     Extended Validation Certificate Requirements:                                  */
    /*       https://www.cabforum.org/Guidelines_v1_4_3.pdf                               */
    /*                                                                                    */
    /* Here are the minimum steps you should perform:                                     */
    /*   1. Call SSL_get_peer_certificate and ensure the certificate is non-NULL. It      */
    /*      should never be NULL because Anonymous Diffie-Hellman (ADH) is not allowed.   */
    /*   2. Call SSL_get_verify_result and ensure it returns X509_V_OK. This return value */
    /*      depends upon your verify_callback if you provided one. If not, the library    */
    /*      default validation is fine (and you should not need to change it).            */
    /*   3. Verify either the CN or the SAN matches the host you attempted to connect to. */
    /*      Note Well (N.B.): OpenSSL prior to version 1.1.0 did *NOT* perform hostname   */
    /*      verification. If you are using OpenSSL 0.9.8 or 1.0.1, then you will need     */
    /*      to perform hostname verification yourself. The code to get you started on     */
    /*      hostname verification is provided in print_cn_name and print_san_name. Be     */
    /*      sure you are sensitive to ccTLDs (don't navively transform the hostname       */
    /*      string). http://publicsuffix.org/ might be helpful.                           */
    /*                                                                                    */
    /* If all three checks succeed, then you have a chance at a secure connection. But    */
    /*   its only a chance, and you should either pin your certificates (to remove DNS,   */
    /*   CA, and Web Hosters from the equation) or implement a Trust-On-First-Use (TOFU)  */
    /*   scheme like Perspectives or SSH. But before you TOFU, you still have to make     */
    /*   the customary checks to ensure the certifcate passes the sniff test.             */
    /*                                                                                    */
    /* Happy certificate validation hunting!                                              */
    /**************************************************************************************/
    /**************************************************************************************/


    /* Step 1: verify a server certifcate was presented during negotiation */
    /* https://www.openssl.org/docs/ssl/SSL_get_peer_certificate.html          */
    X509 *cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        X509_free(cert);
    }                           // free immediately

    ASSERT(NULL != cert);
    if (NULL == cert) {
        /* Hack a code for print_error_string. */
        print_error_string(X509_V_ERR_APPLICATION_VERIFICATION, "SSL_get_peer_certificate");
        //break; /* failed */
    }

    /* Step 2: verify the result of chain verifcation             */
    /* http://www.openssl.org/docs/ssl/SSL_get_verify_result.html */
    /* Error codes: http://www.openssl.org/docs/apps/verify.html  */
    res = SSL_get_verify_result(ssl);

    ASSERT(X509_V_OK == res);
    if (!(X509_V_OK == res)) {
        /* Hack a code into print_error_string. */
        print_error_string((unsigned long) res, "SSL_get_verify_results");
        //break; /* failed */
    }

    /* Step 3: hostname verifcation.   */
    /* An exercise left to the reader. */
    cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        X509_NAME *subject = X509_get_subject_name(cert);
        unsigned char *name = get_cn_name("Peer certificate", subject);
        bool ufp = endsWith(name, "ufp.com");

        OPENSSL_free(name);
        X509_free(cert);

        ASSERT(ufp);
        if (!ufp) {
            print_error_string(X509_V_ERR_APPLICATION_VERIFICATION, "peer certificate not valid");
            //break;
        }
    }

    /**************************************************************************************/
    /**************************************************************************************/
    /* Now, we can finally start reading and writing to the BIO...                        */
    /**************************************************************************************/
    /**************************************************************************************/
    char *query = NULL;
    char str[256];

    sprintf(str, "POST %s HTTP/1.1\r\nHost: %s", path, get_host());
    BIO_puts(web, str);
    BIO_puts(web, "\r\nContent-Type: application/x-www-form-urlencoded");
    query = create_query(parameters);
    sprintf(str, "\r\nContent-Length: %zu", strlen(query));
    BIO_puts(web, str);
    sprintf(str, "\r\n\r\n%s", query);
    BIO_puts(web, str);

    char *response = perform_read(web);
    free(query);
    sm_delete(parameters);
    BIO_free_all(web);
    BIO_free(out);
    return response;
}

#define READ_BUFFER_SIZE 4096
char *perform_read(BIO * web)
{
    BIO *wbio = BIO_new(BIO_s_mem());
    int len = 0;

    const char *msg;
    int pret, minor_version, status;
    struct phr_header headers[100];
    int num_headers;
    size_t data_len = 0, msg_len, last_len = 0;

    num_headers = sizeof(headers) / sizeof(headers[0]);

    /**
     * In testing we either see the entire response come back in the first read and any subsequent read blocks until timeout OR
     * we see the headers come in the first read, the content in the 2nd read, and subsequent reads return immediately with length zero.
     * High coupling to these two scenarios mitigates long blocking operations.
     */

    {
        // first read to either get headers or entire response
        char *buffer = (char *) malloc(READ_BUFFER_SIZE);
        memset(buffer, 0, READ_BUFFER_SIZE);
        /* https://www.openssl.org/docs/crypto/BIO_read.html */

        len = BIO_read(web, buffer, READ_BUFFER_SIZE);
        if (len > 0)
            BIO_write(wbio, buffer, len);
        free(buffer);
    }

    char *data;
    long length = BIO_get_mem_data(wbio, &data);

    // process the response which at least has headers
    char *response = NULL;
    pret = phr_parse_response(data, length, &minor_version, &status, &msg, &msg_len, headers, (size_t *) & num_headers, last_len);
    if (pret > 0) {
        int i = 0;

        int data_length = 0;
        for (i = 0; i != num_headers; ++i) {
            if (strncasecmp(headers[i].name, "Content-Length", headers[i].name_len) == 0) {
                data_length = atoi(headers[i].value);
            }
        }

        // 2nd+ reads to get the content
        while (length < pret+data_length) {
            int size = pret+data_length - length;
            char *buffer = (char *) malloc(size);
            memset(buffer, 0, size);
            int len = BIO_read(web, buffer, size);
            if (len > 0) {
                BIO_write(wbio, buffer, len);
                /* BIO_should_retry returns TRUE unless there's an  */
                /* error. We expect an error when the server        */
                /* provides the response and closes the connection. */
            }
            free(buffer);
            length = BIO_get_mem_data(wbio, &data);
        }

        if ((status == 200) && (data_length > 0)) {
            response = (char *) malloc(data_length + 1);
            memset(response, 0, data_length + 1);
            memcpy(response, data + pret, data_length);
        } else
            asprintf(&response, IDENTITY_ERROR_XML, status);

    } else if (pret <= 0) {
        fprintf(stderr, "error parsing: %d\n", pret);
        asprintf(&response, IDENTITY_ERROR_XML, 500);
    }
    BIO_free_all(wbio);
    return response;
}

static void iter(const char *key, const char *value, const void *obj)
{
    char *buffer = (char *) obj;
    sprintf(buffer + strlen(buffer), "%s=%s&", key, value);
}

#define QUERY_BUFFER_SIZE 1028
char *create_query(StrMap * parameters)
{
    char *query_buffer = (char *) malloc(QUERY_BUFFER_SIZE);
    memset(query_buffer, 0, QUERY_BUFFER_SIZE);
    sm_enum(parameters, iter, query_buffer);
    query_buffer[strlen(query_buffer) - 1] = '\0';
    return query_buffer;
}

int verify_callback(int preverify, X509_STORE_CTX * x509_ctx)
{
    /* For error codes, see http://www.openssl.org/docs/apps/verify.html  */

    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    int err = X509_STORE_CTX_get_error(x509_ctx);

    X509 *cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME *iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME *sname = cert ? X509_get_subject_name(cert) : NULL;

    //fprintf(stdout, "verify_callback (depth=%d)(preverify=%d)\n", depth, preverify);

    /* Issuer is the authority we trust that warrants nothing useful */
    //print_cn_name("Issuer (cn)", iname);

    /* Subject is who the certificate is issued to by the authority  */
    //print_cn_name("Subject (cn)", sname);

    if (depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs */
        //print_san_name("Subject (san)", cert);
    }

    if (preverify == 0) {
        if (err == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
            fprintf(stdout, "  Error = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY\n");
        else if (err == X509_V_ERR_CERT_UNTRUSTED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_UNTRUSTED\n");
        else if (err == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN)
            fprintf(stdout, "  Error = X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN\n");
        else if (err == X509_V_ERR_CERT_NOT_YET_VALID)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_NOT_YET_VALID\n");
        else if (err == X509_V_ERR_CERT_HAS_EXPIRED)
            fprintf(stdout, "  Error = X509_V_ERR_CERT_HAS_EXPIRED\n");
        else if (err == X509_V_OK)
            fprintf(stdout, "  Error = X509_V_OK\n");
        else
            fprintf(stdout, "  Error = %d\n", err);
    }
#if !defined(NDEBUG)
    return 1;
#else
    return preverify;
#endif
}

unsigned char *get_cn_name(const char *label, X509_NAME * const name)
{
    int idx = -1;
    unsigned char *utf8 = NULL;

    do {
        if (!name)
            break;              /* failed */

        idx = X509_NAME_get_index_by_NID(name, NID_commonName, -1);
        if (!(idx > -1))
            break;              /* failed */

        X509_NAME_ENTRY *entry = X509_NAME_get_entry(name, idx);
        if (!entry)
            break;              /* failed */

        ASN1_STRING *data = X509_NAME_ENTRY_get_data(entry);
        if (!data)
            break;              /* failed */

        int length = ASN1_STRING_to_UTF8(&utf8, data);
        if (!utf8 || !(length > 0))
            break;              /* failed */

    } while (0);
    return utf8;
}

void print_error_string(unsigned long err, const char *const label)
{
    const char *const str = ERR_reason_error_string(err);
    if (str)
        fprintf(stderr, "%s\n", str);
    else
        fprintf(stderr, "%s failed: %lu (0x%lx)\n", label, err, err);
}

void init_openssl_library(void)
{
    /* https://www.openssl.org/docs/ssl/SSL_library_init.html */
    (void) SSL_library_init();
    /* Cannot fail (always returns success) ??? */

    /* https://www.openssl.org/docs/crypto/ERR_load_crypto_strings.html */
    SSL_load_error_strings();
    /* Cannot fail ??? */

    /* SSL_load_error_strings loads both libssl and libcrypto strings */
    /* ERR_load_crypto_strings(); */
    /* Cannot fail ??? */

    /* OpenSSL_config may or may not be called internally, based on */
    /*  some #defines and internal gyrations. Explicitly call it    */
    /*  *IF* you need something from openssl.cfg, such as a         */
    /*  dynamically configured ENGINE.                              */
    OPENSSL_config(NULL);
    /* Cannot fail ??? */

    /* Include <openssl/opensslconf.h> to get this define     */
#if defined (OPENSSL_THREADS)
    /* TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO TODO */
    /* https://www.openssl.org/docs/crypto/threads.html */
    //fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif
}
