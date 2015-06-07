#include <stdio.h>
#include <ifaddrs.h>

#include "identity.h"
#include "identity-openssl-bridge.h"
#include "identity-xml-parser.h"

char *get_clientip()
{
    struct ifaddrs *ifaddr, *ifa;
    int n, family;
    char *clientip = (char *) malloc(NI_MAXHOST);

    getifaddrs(&ifaddr);
    for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
        if (ifa->ifa_addr == NULL)
            continue;
        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET || family == AF_INET6) {
            if (strcmp(ifa->ifa_name, "lo") != 0) {
                getnameinfo(ifa->ifa_addr, (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6), clientip, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
                break;
            }
        }
    }
    freeifaddrs(ifaddr);
    return clientip;
}

/**
 * if key_file_name is NULL, use certificate_file_name
 */
identity_context_t *get_identity_context(char *certificate_file_name, char *truststore_file_name, char *key_file_name, char *key_password)
{
    identity_context_t *identity_context = (identity_context_t *) malloc(sizeof(identity_context_t));
    if (identity_context != NULL)
        ssl_initialize_identity_context(identity_context, certificate_file_name, truststore_file_name, key_file_name, key_password);
    return identity_context;
}

void free_identity_context(identity_context_t * identity_context)
{
    if (identity_context != NULL) {
        ssl_free_identity_context(identity_context);
        free(identity_context);
    }
}

authentication_pretext_t *pre_authenticate(identity_context_t * identity_context, const char *name, StrMap * sm)
{
    sm_put(sm, "name", name);
    char *clientip = get_clientip();
    sm_put(sm, "client_ip", clientip);
    free(clientip);
    char *xml = send_message(identity_context, "/identity-services/services/preauthenticate", sm);
    authentication_pretext_t *authentication_pretext = parse_authentication_pretext(xml);
    free(xml);
    return authentication_pretext;
}

authentication_context_t *authenticate(identity_context_t * identity_context, char *name, StrMap * sm)
{
    sm_put(sm, "name", name);
    char *clientip = get_clientip();
    sm_put(sm, "client_ip", clientip);
    free(clientip);
    char *xml = send_message(identity_context, "/identity-services/services/authenticate", sm);
    authentication_context_t *authentication_context = parse_authentication_context(xml);
    free(xml);
    return authentication_context;
}

#ifndef __PIC__
int main(int argc, char **argv)
{
    identity_context_t *identity_context = get_identity_context("example.com.pem", "truststore.pem", NULL, "test");

    authentication_pretext_t *authentication_pretext = pre_authenticate(identity_context, "guest", sm_new(10));
    if (strcmp(authentication_pretext->authentication_result->message, "OK") == 0 && (strcmp(authentication_pretext->authentication_result->text, "SUCCESS") == 0)) {
        StrMap *sm = sm_new(10);
        sm_put(sm, authentication_pretext->display_items->name, "guest");
        authentication_context_t *authentication_context = authenticate(identity_context, authentication_pretext->name, sm);
        free_authentication_context(authentication_context);
    }
    free_authentication_pretext(authentication_pretext);

    free_identity_context(identity_context);
}
#endif
