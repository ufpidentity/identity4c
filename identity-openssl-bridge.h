#ifndef __IDENTITY_OPENSSL_BRIDGE_H__
#define __IDENTITY_OPENSSL_BRIDGE_H__

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <assert.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/ssl.h>
#include <openssl/bio.h>
#include <openssl/engine.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509.h>
#include <openssl/buffer.h>
#include <openssl/x509v3.h>
#include <openssl/opensslconf.h>

#ifndef UNUSED
# define UNUSED(x) ((void)(x))
#endif

#ifndef TRUE
# define TRUE 1
#endif

#ifndef FALSE
# define FALSE 0
#endif

/*******************************************/
/* Diagnostics and ASSERT                  */
/*******************************************/

#if !defined(NDEBUG)

#include <signal.h>

static void NullTrapHandler(int unused) { UNUSED(unused); }

// No reason to return a value even though the function can fail.
// Its not like we can assert to alert of a failure.
static int InstallDebugTrapHandler()
{
    // http://pubs.opengroup.org/onlinepubs/007908799/xsh/sigaction.html
    struct sigaction new_handler, old_handler;
    
    int ret = 0;
    
    do {
        ret = sigaction (SIGTRAP, NULL, &old_handler);
        if (ret != 0) break; // Failed
        
        // Don't step on another's handler
        // if (old_handler.sa_handler != NULL) {
        //    ret = 0;
        //    break;
        // }
        
        // Set up the structure to specify the null action.
        new_handler.sa_handler = &NullTrapHandler;
        new_handler.sa_flags = 0;
        
        ret = sigemptyset (&new_handler.sa_mask);
        if (ret != 0) break; // Failed
        
        // Install it
        ret = sigaction (SIGTRAP, &new_handler, NULL);
        if (ret != 0) break; // Failed
        
        ret = 0;
        
    } while(0);
    
    return ret;
}

#  define ASSERT(x) { \
  if(!(x)) { \
    fprintf(stderr, "Assertion: %s: function %s, line %d\n", (char*)(__FILE__), (char*)(__func__), (int)__LINE__); \
    raise(SIGTRAP); \
  } \
}

#else

#  define ASSERT(x) UNUSED(x)

#endif // !defined(NDEBUG)

void ssl_initialize_identity_context(identity_context_t *identity_context, char *certificate_file_name, char *truststore_file_name, char *key_file_name, char *key_password);
void ssl_free_identity_context(identity_context_t *identity_context);
char *send_message(identity_context_t *identity_context, char *path, StrMap *parameters);
#endif /* __IDENTITY_OPENSSL_BRIDGE_H__ */
