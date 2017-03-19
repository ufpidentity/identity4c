#ifndef __IDENTITY_H__
#define __IDENTITY_H__
#include <openssl/ssl.h>
#include "strmap.h"

struct result {
    int code;
    int level;
    double confidence;
    char *message;
    char *text;
};

typedef struct result result_t;

struct display_item {
    char *name;
    char *reset;
    char *display_name;
    char *form_element;
    char *nickname;
    struct display_item *next;
};

typedef struct display_item display_item_t;

struct authentication_pretext {
    char *name;
    result_t *authentication_result; // just one
    display_item_t *display_items; // array
};

struct authentication_context {
    char *name;
    result_t *authentication_result; // just one
};

struct identity_context {
    SSL_CTX *ssl_ctx;
};

typedef struct authentication_pretext authentication_pretext_t;

// stubs
typedef struct authentication_context authentication_context_t;
typedef struct identity_context identity_context_t;

identity_context_t *get_identity_context(char *certificate_file_name, char *truststore_file_name, char *key_file_name, char *key_password);
void free_identity_context(identity_context_t *identity_context);

authentication_pretext_t *pre_authenticate(identity_context_t *context, const char *name, StrMap *sm);
void free_authentication_pretext(authentication_pretext_t *authentication_pretext);

authentication_context_t *authenticate(identity_context_t *context, char *name, StrMap *sm);
void free_authentication_context(authentication_context_t *authentication_context);

// management API
char *management(identity_context_t *context, StrMap *sm);
char *management_find(identity_context_t *context, StrMap *sm);
#endif /* __IDENTITY_H__ */
