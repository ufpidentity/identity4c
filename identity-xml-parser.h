#ifndef __IDENTITY_XML_PARSER_H__
#define __IDENTITY_XML_PARSER_H__
#include "identity.h"
authentication_context_t *parse_authentication_context(char *xml);
authentication_pretext_t *parse_authentication_pretext(char *xml);
#endif /* __IDENTITY_XML_PARSER_H__ */
