#include <stdio.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include "identity.h"
#include "identity-xml-parser.h"

static char *copy_string(char *src)
{
    char *dest = NULL;
    dest = (char *) malloc(strlen(src) + 1);
    memset(dest, 0, strlen(src) + 1);
    memcpy(dest, src, strlen(src));
    return dest;
}

static result_t *parse_result(xmlNode * a_node)
{
    result_t *result = malloc(sizeof(result_t));

    result->text = copy_string(a_node->children->content);
    xmlAttr *cur_attr = NULL;
    for (cur_attr = a_node->properties; cur_attr; cur_attr = cur_attr->next) {
        if (cur_attr->type == XML_ATTRIBUTE_NODE) {
            if (strcmp(cur_attr->name, "code") == 0) {
                result->code = strtol(cur_attr->children->content, (char **) NULL, 10);
            } else if (strcmp(cur_attr->name, "level") == 0) {
                result->level = strtol(cur_attr->children->content, (char **) NULL, 10);
            } else if (strcmp(cur_attr->name, "confidence") == 0) {
                result->confidence = strtod(cur_attr->children->content, (char **) NULL);
            } else if (strcmp(cur_attr->name, "message") == 0) {
                char *message = cur_attr->children->content;
                result->message = copy_string(message);
            }
        }
    }
    return result;
}

static void free_result(result_t * result)
{
    if (result->message != NULL)
        free(result->message);
    if (result->text != NULL)
        free(result->text);
    free(result);
}

static void parse_display_item(display_item_t * display_item, xmlNode * a_node)
{
    // first parse out the attributes
    xmlAttr *cur_attr = NULL;
    for (cur_attr = a_node->properties; cur_attr; cur_attr = cur_attr->next) {
        if (cur_attr->type == XML_ATTRIBUTE_NODE) {
            if (strcmp(cur_attr->name, "name") == 0) {
                display_item->name = copy_string(cur_attr->children->content);
            } else if (strcmp(cur_attr->name, "reset") == 0) {
                display_item->reset = copy_string(cur_attr->children->content);
            }
        }
    }
    // now parse out the elements
    xmlNode *cur_node = NULL;
    while (a_node != NULL) {
        for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE) {
                if (strcmp(cur_node->name, "display_name") == 0) {
                    display_item->display_name = copy_string(cur_node->children->content);
                } else if (strcmp(cur_node->name, "form_element") == 0) {
                    display_item->form_element = copy_string(cur_node->children->content);
                } else if (strcmp(cur_node->name, "nickname") == 0) {
                    display_item->nickname = copy_string(cur_node->children->content);
                }
            }
        }
        a_node = a_node->children;
    }
}

static void free_display_items(display_item_t * display_items)
{
    display_item_t *display_item = display_items;
    display_item_t *next_display_item = NULL;

    while (display_item != NULL) {
        next_display_item = display_item->next;
        free(display_item->name);
        free(display_item->reset);
        free(display_item->display_name);
        free(display_item->form_element);
        free(display_item->nickname);
        free(display_item);
        display_item = next_display_item;
    }
}

/**
 * parse_authentication_pretext:
 * @a_node: the initial xml node to consider.
 *
 * Parses an XML representation of an authentication pretext into an
 * struct representing the pretext.
 */
static authentication_pretext_t *walk_authentication_pretext_node(xmlNode * a_node)
{
    xmlNode *cur_node = NULL;
    authentication_pretext_t *authentication_pretext = malloc(sizeof(authentication_pretext_t));
    memset(authentication_pretext, 0, sizeof(authentication_pretext_t));
    while (a_node != NULL) {
        for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE) {
                if (strcmp(cur_node->name, "name") == 0)
                    authentication_pretext->name = copy_string(cur_node->children->content);
                else if (strcmp(cur_node->name, "result") == 0)
                    authentication_pretext->authentication_result = parse_result(cur_node);
                else if (strcmp(cur_node->name, "display_item") == 0) {
                    if (authentication_pretext->display_items == NULL) {
                        authentication_pretext->display_items = malloc(sizeof(display_item_t));
                        memset(authentication_pretext->display_items, 0, sizeof(display_item_t));
                        parse_display_item(authentication_pretext->display_items, cur_node);
                    } else {
                        display_item_t *display_item = authentication_pretext->display_items;
                        while (display_item->next != NULL)
                            display_item = display_item->next;
                        display_item->next = malloc(sizeof(display_item_t));
                        memset(display_item->next, 0, sizeof(display_item_t));
                        parse_display_item(display_item->next, cur_node);
                    }
                }
            }
        }
        a_node = a_node->children;
    }
    return authentication_pretext;
}

/**
 * parse_authentication_context:
 * @a_node: the initial xml node to consider.
 *
 * Parses an XML representation of an authentication context into an
 * struct representing the context.
 */
static authentication_context_t *walk_authentication_context_node(xmlNode * a_node)
{
    xmlNode *cur_node = NULL;
    authentication_context_t *authentication_context = malloc(sizeof(authentication_context_t));
    memset(authentication_context, 0, sizeof(authentication_context_t));
    while (a_node != NULL) {
        for (cur_node = a_node; cur_node; cur_node = cur_node->next) {
            if (cur_node->type == XML_ELEMENT_NODE) {
                if (strcmp(cur_node->name, "name") == 0)
                    authentication_context->name = copy_string(cur_node->children->content);
                else if (strcmp(cur_node->name, "result") == 0)
                    authentication_context->authentication_result = parse_result(cur_node);
            }
        }
        a_node = a_node->children;
    }
    return authentication_context;
}

authentication_pretext_t *parse_authentication_pretext(char *xml)
{
    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;

    doc = xmlReadDoc(xml, "authentication_pretext.xml", NULL, 0);
    root_element = xmlDocGetRootElement(doc);
    authentication_pretext_t *authentication_pretext = walk_authentication_pretext_node(root_element);
    xmlFreeDoc(doc);
    xmlCleanupParser();
    return authentication_pretext;

}

authentication_context_t *parse_authentication_context(char *xml)
{
    xmlDoc *doc = NULL;
    xmlNode *root_element = NULL;

    doc = xmlReadDoc(xml, "authentication_context.xml", NULL, 0);
    root_element = xmlDocGetRootElement(doc);
    authentication_context_t *authentication_context = walk_authentication_context_node(root_element);
    xmlFreeDoc(doc);
    xmlCleanupParser();
    return authentication_context;
}

void free_authentication_pretext(authentication_pretext_t * authentication_pretext)
{
    free(authentication_pretext->name);
    free_result(authentication_pretext->authentication_result);
    free_display_items(authentication_pretext->display_items);
    free(authentication_pretext);
}

void free_authentication_context(authentication_context_t * authentication_context)
{
    free(authentication_context->name);
    free_result(authentication_context->authentication_result);
    free(authentication_context);
}
