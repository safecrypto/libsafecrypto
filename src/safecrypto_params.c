/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/*
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

#include "safecrypto_params.h"
#include "safecrypto_debug.h"
#include "safecrypto_private.h"

#include <string.h>


sc_param_t * find_node(safecrypto_t *sc, const char *alg, const char *name)
{
    sc_param_t *node = NULL;

    if (NULL == sc || NULL == alg || NULL == name) {
        return NULL;
    }

    // Cycle through the nodes until a NULL node pointer is found OR
    // a node with the algorithm name and parameter name is found
    node = sc->params;
    while (node) {
        if (strcmp(node->alg, alg) == 0) {
            if (strcmp(node->name, name) == 0) {
                SAFECRYPTO_DEBUG(sc, "Found node with alg %s and name %s\n", alg, name);
                break;
            }
        }
        node = node->next;
    }

    return node;
}

sc_param_t * create_node(safecrypto_t *sc, const char *alg, const char *name,
    sc_param_type_e type, sc_data_u value, size_t length)
{
    sc_param_t *node = NULL;
    sc_param_t *prev = NULL;

    if (NULL == sc || NULL == alg || NULL == name) {
        return NULL;
    }

    // Check if the node already exists
    node = find_node(sc, alg, name);
    if (node) {
        SAFECRYPTO_DEBUG(sc, "Create failed as already exists, alg: %s and name: %s\n", alg, name);
        return NULL;
    }

    // Cycle through the nodes until a NULL node pointer is found    
    node = sc->params;
    while (node) {
        prev = node;
        node = node->next;
    }
    node = SC_MALLOC(sizeof(sc_param_t));
    if (node) {
        // Copy data to the just created node
        SAFECRYPTO_STRCPY(node->alg, alg, SC_MAX_NAME_LEN);
        SAFECRYPTO_STRCPY(node->name, name, SC_MAX_NAME_LEN);
        node->type = type;
        node->value = value;
        node->length = length;
        node->next = NULL;
        node->prev = prev;
        if (prev) prev->next = node;

        // If the root node is null set it to the just created node
        if (NULL == sc->params) {
            sc->params = node;
        }
    }

    return node;
}

SINT32 remove_node(safecrypto_t *sc, const char *alg, const char *name)
{
    sc_param_t *node = NULL;
    sc_param_t *prev = NULL;
    sc_param_t *next = NULL;

    if (NULL == sc || NULL == alg || NULL == name) {
        return SC_FUNC_FAILURE;
    }

    // Check if the node exists
    node = find_node(sc, alg, name);
    if (NULL == node) {
        return SC_FUNC_FAILURE;
    }

    // Cycle through the nodes until the selected parameter is found,
    // then remove that parameter from the linked list
    node = sc->params;
    while (node) {
        next = node->next;
        prev = node->prev;
        if (0 == strcmp(node->alg, alg)) {
            if (prev) prev->next = next;
            if (next) next->prev = prev;
            SC_FREE(node, sizeof(sc_param_t));
            return SC_FUNC_SUCCESS;
        }
        node = next;
    }

    return SC_FUNC_FAILURE;
}


SINT32 params_create(safecrypto_t *sc)
{
    if (sc == NULL) {
        return SC_FUNC_FAILURE;
    }

    sc->params = NULL;
    return SC_FUNC_SUCCESS;
}

SINT32 params_destroy(safecrypto_t *sc)
{
    sc_param_t *node = NULL;
    sc_param_t *next = NULL;

    if (NULL == sc) {
        return SC_FUNC_FAILURE;
    }

    // Cycle through the nodes until a NULL node pointer is found    
    node = sc->params;
    while (node) {
        next = node->next;
        SC_FREE(node, sizeof(sc_param_t));
        node = next;
    }

    return SC_FUNC_SUCCESS;
}

SINT32 params_clear(safecrypto_t *sc, const char *alg)
{
    sc_param_t *node = NULL;
    sc_param_t *prev = NULL;
    sc_param_t *next = NULL;

    if (NULL == sc || NULL == alg) {
        return SC_FUNC_FAILURE;
    }

    // Cycle through the nodes removing all parameters associated with
    // the specified algorithm
    node = sc->params;
    while (node) {
        next = node->next;
        if (0 == strcmp(node->alg, alg)) {
            if (prev) prev->next = node->next;
            SC_FREE(node, sizeof(sc_param_t));
        }
        else {
            prev = node;
        }
        node = next;
    }

    return SC_FUNC_SUCCESS;
}

SINT32 params_add(safecrypto_t *sc, const char *alg, const char *name,
    sc_param_type_e type, sc_data_u value)
{
    sc_param_t *param;

    param = create_node(sc, alg, name, type, value, 1);

    if (NULL == param) {
        return SC_FUNC_FAILURE;
    }
    else {
        return SC_FUNC_SUCCESS;
    }
}

SINT32 params_add_array(safecrypto_t *sc, const char *alg, const char *name,
    sc_param_type_e type, const void* array, size_t length)
{
    sc_param_t *param;
    sc_data_u value;

    if (NULL == array) {
        return SC_FUNC_FAILURE;
    }

    value.v = array;
    param = create_node(sc, alg, name, type, value, length);

    if (NULL == param) {
        return SC_FUNC_FAILURE;
    }
    else {
        return SC_FUNC_SUCCESS;
    }
}

SINT32 params_remove(safecrypto_t *sc, const char *alg, const char *name)
{
    // Remove the node and return
    return remove_node(sc, alg, name);
}

SINT32 params_get(safecrypto_t *sc, const char *alg, const char *name,
    sc_param_type_e *type, sc_data_u *value, size_t *length)
{
    sc_param_t *node = NULL;

    if (NULL == sc || NULL == alg || NULL == name) {
        return SC_FUNC_FAILURE;
    }

    // Check if the node exists
    node = find_node(sc, alg, name);
    if (NULL == node) {
        return SC_FUNC_FAILURE;
    }

    *type = node->type;
    *value = node->value;
    *length = node->length;

    return SC_FUNC_SUCCESS;
}
