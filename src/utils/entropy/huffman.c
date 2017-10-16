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

#include "huffman.h"
#include "safecrypto_private.h"
#include "utils/crypto/prng.h"
#include <math.h>
#include "utils/arith/sc_math.h"

typedef struct tree_node_t tree_node_t;

/// A struct used to act as a node when constructing a Huffman tree
typedef struct tree_node_t {
    SINT16 value;
    UINT64 freq;
    tree_node_t *left;
    tree_node_t *right;
} tree_node_t;

///  A pool of Huffman nodes used for temporary storage
typedef struct huff_pool_t {
    tree_node_t *nodes;
    SINT32      n;
} huff_pool_t;

/// A struct used to store a priority queue of tree_node_t objects
typedef struct priority_queue_t {
    tree_node_t **qqq;
    tree_node_t **q;
    SINT32      qend;
} priority_queue_t;


/** @brief Move a node from the pool and assign the correct left/right, value and frequency values.
 *
 *  @param pool A pointer to a pool of pre-allocated tree_node_t objects
 *  @param freq The frequency of occurence of the symbol
 *  @param value The symbol value
 *  @param a A pointer to the left hand node of the tree
 *  @param b A pointer to the right hand node of the tree
 *  @return A tree_node_t pointer to the created node
 */
tree_node_t * create_node(huff_pool_t *pool, UINT64 freq, SINT16 value, tree_node_t *a, tree_node_t *b)
{
    tree_node_t *node = pool->nodes + pool->n++;
    if (freq > 0) {
        node->value = value;
        node->freq  = freq;
    }
    else {
        node->value = -1;
        node->left  = a;
        node->right = b;
        node->freq  = a->freq + b->freq;
    }
    return node;
}

/** @brief Insert the specified node into the queue
 *
 *  @param queue The queue of tree_node_t objects
 *  @param node A pointer to the tree_node_t object to be inserted
 */
void queue_insert(priority_queue_t *queue, tree_node_t *node)
{
    SINT32 j, i = queue->qend++;
    while ((j = i / 2)) {
        if (queue->q[j]->freq <= node->freq) {
            break;
        }
        queue->q[i] = queue->q[j];
        i = j;
    }
    queue->q[i] = node;
}
 
/** @brief Remove the node at the head of the queue
 *
 *  @param queue The queue of tree_node_t objects
 *  @return A pointer to the tree_node_t object that was at the head of the queue
 */
tree_node_t * queue_remove(priority_queue_t *queue)
{
    SINT32 i, l;
    tree_node_t *node = queue->q[i = 1];
 
    if (queue->qend < 2) {
        return 0;
    }

    queue->qend--;
    while ((l = i * 2) < queue->qend) {
        if (l + 1 < queue->qend && queue->q[l + 1]->freq < queue->q[l]->freq) {
            l++;
        }
        queue->q[i] = queue->q[l], i = l;
    }
    queue->q[i] = queue->q[queue->qend];

    return node;
}

/** @brief A recursive function used to build a Huffman code tree for encoding
 *
 *  @param node A pointer to the current tree node
 *  @param codes A pointer to the code tree being built
 *  @param cur_code The current codeword
 *  @param len The length of the codeword
 *  @return A standard error code
 */
SINT32 huffman_codes(tree_node_t *node, huffman_code_t *codes, UINT32 cur_code, SINT32 len)
{
    SINT32 retcode;

    if (len > 32) {
        return SC_FUNC_FAILURE;
    }

    if (node->value >= 0) {
        codes[node->value].code = cur_code;
        codes[node->value].bits = len;

        return SC_FUNC_SUCCESS;
    }

    len++;

    retcode = huffman_codes(node->left,  codes, (cur_code << 1)    , len);
    if (SC_FUNC_SUCCESS == retcode) {
        retcode = huffman_codes(node->right, codes, (cur_code << 1) | 1, len);
        return retcode;
    }

    return SC_FUNC_FAILURE;
}

/** @brief A recursive function used to build a Huffman code tree for encoding (64-bit)
 *
 *  @param node A pointer to the current tree node
 *  @param codes A pointer to the code tree being built
 *  @param cur_code The current codeword
 *  @param len The length of the codeword
 *  @return A standard error code
 */
SINT32 huffman_codes_64(tree_node_t *node, huffman_code_64_t *codes, UINT64 cur_code, SINT32 len)
{
    SINT32 retcode;

    if (len > 64) {
        return SC_FUNC_FAILURE;
    }

    if (node->value >= 0) {
        codes[node->value].code = cur_code;
        codes[node->value].bits = len;

        return SC_FUNC_SUCCESS;
    }

    len++;

    retcode = huffman_codes_64(node->left,  codes, (cur_code << 1)    , len);
    if (SC_FUNC_SUCCESS == retcode) {
        retcode = huffman_codes_64(node->right, codes, (cur_code << 1) | 1, len);
        return retcode;
    }

    return SC_FUNC_FAILURE;
}

/** @brief A recursive function used to build a Huffman tree LUT for decoding purposes
 *
 *  @param node A pointer to the current tree node
 *  @param nodes A pointer to the node LUT being built
 *  @param index The current node LUT index
 *  @return The updated index code
 */
SINT32 huffman_tree(tree_node_t *node, huffman_node_t *nodes, SINT32 index)
{
    SINT32 idx = index;

    if (node->value >= 0) {
        nodes[idx].left  = -1;
        nodes[idx].right = node->value;

        return idx + 1;
    }

    index++;

    nodes[idx].left  = index;
    index = huffman_tree(node->left,  nodes, index);
    nodes[idx].right = index;
    index = huffman_tree(node->right, nodes, index);

    return index;
}

/** @brief Generate a Huffman code and node LUTs for use as in entropy coding
 *
 *  @param bits The desired bit width of the output samples
 *  @param sigma The standard deviation of the distribution
 *  @return A pointer to the Huffman table to be used for entropy coding
 */
huffman_table_t * create_huffman_gaussian(SINT32 bits, FLOAT sigma)
{
    size_t i;
    size_t n = 1 << bits;

    // Allocate memory resources for intermediate data and the output LUTs
    UINT64 *p = SC_MALLOC(n * sizeof(UINT64));
    huff_pool_t pool;
    pool.nodes = SC_MALLOC(2 * n * sizeof(tree_node_t));
    memset(pool.nodes, 0, 2 * n * sizeof(tree_node_t));
    priority_queue_t tree;
    tree.qqq = SC_MALLOC((2 * n - 1) * sizeof(tree_node_t*));
    huffman_table_t *table = SC_MALLOC(sizeof(huffman_table_t));
    table->nodes = SC_MALLOC((2 * n - 1) * sizeof(huffman_node_t));
    table->codes = SC_MALLOC(n * sizeof(huffman_code_t));
    table->codes_64 = NULL;
    table->depth = n;

    tree.q = tree.qqq - 1;
    tree.qend = 1;
    pool.n = 0;

    // Create a probability distribution based on a Gaussian distribution
    // with standard deviation sigma
    LONGDOUBLE d = 0.398942280401433L * 18446744073709551616.0L / sigma;
    LONGDOUBLE e = -1 / (2 * sigma * sigma);
    for (i=0; i<n; i++) {
        p[i] = d * expl(e * (LONGDOUBLE)(i * i));
    }

    // Initialise the Huffman tree with symbol indices
    for (i = 0; i < n; i++) {
        if (p[i] > 0) {
            tree_node_t *init_node = create_node(&pool, p[i], i, NULL, NULL);
            queue_insert(&tree, init_node);
        }
    }

    // Build the Huffman tree
    while (tree.qend > 2) {
        tree_node_t *a = queue_remove(&tree);
        tree_node_t *b = queue_remove(&tree);
        tree_node_t *c = create_node(&pool, 0, 0, a, b);
        queue_insert(&tree, c);
    }

    // Create the Huffman coding LUT, if it fails try again with a 64-bit code variant
    SINT32 retcode = huffman_codes(tree.q[1], (huffman_code_t*)table->codes, 0, 0);
    if (SC_FUNC_FAILURE == retcode) {
        void *codes = (void*) table->codes;
        SC_FREE(codes, n * sizeof(huffman_code_t));
        table->codes = NULL;
        table->codes_64 = SC_MALLOC(n * sizeof(huffman_code_64_t));
        retcode = huffman_codes_64(tree.q[1], (huffman_code_64_t*)table->codes_64, 0, 0);
        if (SC_FUNC_FAILURE == retcode) {
            void *nodes = (void*) table->nodes;
            codes = (void*) table->codes_64;
            SC_FREE(nodes, (2 * n - 1) * sizeof(huffman_node_t));
            SC_FREE(codes, n * sizeof(huffman_code_64_t));
            SC_FREE(table, sizeof(huffman_table_t));
            goto finish;
        }
    }

    // Translate the Huffman tree nodes into a huffman_node_t LUT whilst simultaneously
    // generating the encoder's code table
    huffman_tree(tree.q[1], (huffman_node_t*)table->nodes, 0);

    // Free resources associated with intermediate storage
finish:
    SC_FREE(p, n * sizeof(UINT64));
    SC_FREE(pool.nodes, 2 * n * sizeof(tree_node_t));
    SC_FREE(tree.qqq, (2 * n - 1) * sizeof(tree_node_t*));

    return table;
}

huffman_table_t * create_huffman_gaussian_sampler(SINT32 bits, FLOAT sigma)
{
    SINT32 i;
    SINT32 n = 1 << bits;

    // Allocate memory resources for intermediate data and the output LUTs
    UINT64 *p = SC_MALLOC(n * sizeof(UINT64));
    huff_pool_t pool;
    pool.nodes = SC_MALLOC(2 * n * sizeof(tree_node_t));
    memset(pool.nodes, 0, 2 * n * sizeof(tree_node_t));
    priority_queue_t tree;
    tree.qqq = SC_MALLOC((2 * n - 1) * sizeof(tree_node_t*));
    huffman_table_t *table = SC_MALLOC(sizeof(huffman_table_t));
    table->nodes = SC_MALLOC((2 * n - 1) * sizeof(huffman_node_t));
    table->codes = NULL;
    table->codes_64 = NULL;
    table->depth = n;

    tree.q = tree.qqq - 1;
    tree.qend = 1;
    pool.n = 0;

    // Create a probability distribution based on a Gaussian distribution
    // with standard deviation sigma
    LONGDOUBLE d = 0.7978845608028653558798L / sigma;
    LONGDOUBLE e = -0.5L / (sigma * sigma);
    for (i=0; i<n; i++) {
        p[i] = get_binary_expansion_fraction_64(d * expl(e * (LONGDOUBLE)(i * i)));
    }

    // Initialise the Huffman tree with symbol indices
    for (i = 0; i < n; i++) {
        if (p[i] > 0) {
            tree_node_t *init_node = create_node(&pool, p[i], i, NULL, NULL);
            queue_insert(&tree, init_node);
        }
    }

    // Build the Huffman tree
    while (tree.qend > 2) {
        tree_node_t *a = queue_remove(&tree);
        tree_node_t *b = queue_remove(&tree);
        tree_node_t *c = create_node(&pool, 0, 0, a, b);
        queue_insert(&tree, c);
    }

    // Translate the Huffman tree nodes into a huffman_node_t LUT whilst simultaneously
    // generating the encoder's code table
    huffman_tree(tree.q[1], (huffman_node_t*)table->nodes, 0);

    // Free resources associated with intermediate storage
    SC_FREE(p, n * sizeof(UINT64));
    SC_FREE(pool.nodes, 2 * n * sizeof(tree_node_t));
    SC_FREE(tree.qqq, (2 * n - 1) * sizeof(tree_node_t*));

    return table;
}

/// Free resources associated with a Huffman table struct
SINT32 destroy_huffman(huffman_table_t **table)
{
    huffman_table_t *l_table = *table;
    void *nodes = (void*) l_table->nodes;
    void *codes = (void*) l_table->codes;
    void *codes_64 = (void*) l_table->codes_64;
    SC_FREE(nodes, (2 * l_table->depth - 1) * sizeof(huffman_node_t));
    if (NULL != codes) SC_FREE(codes, l_table->depth * sizeof(huffman_code_t));
    if (NULL != codes_64) SC_FREE(codes_64, l_table->depth * sizeof(huffman_code_64_t));
    SC_FREE(*table, sizeof(huffman_table_t));
    return SC_FUNC_SUCCESS;
}

SINT32 encode_huffman(sc_packer_t *packer, const huffman_table_t *table, UINT32 value)
{
    if (NULL == packer || NULL == table) {
        return SC_NULL_POINTER;
    }
    if (value >= table->depth) {
        return SC_OUT_OF_BOUNDS;
    }

    UINT32 code = table->codes[value].code;
    UINT16 bits = table->codes[value].bits;

    if (SC_FUNC_FAILURE == packer->write(packer, code, bits)) {
        return SC_ERROR;
    }

    return SC_OK;
}

SINT32 decode_huffman(sc_packer_t *packer, const huffman_table_t *table, UINT32 *value)
{
    UINT32 bit;

    const huffman_node_t *node = table->nodes;
    while (node->left != -1) {
        if (!packer->read(packer, &bit, 1)) {
            return SC_OUT_OF_BOUNDS;
        }

        node = &table->nodes[bit ? node->right : node->left];
    }

    *value = node->right;

    return SC_OK;
}

SINT32 sample_huffman(prng_ctx_t *prng_ctx, const huffman_table_t *table, SINT32 *value)
{
    SINT32 bit;
    UINT32 bits;

    bits = prng_32(prng_ctx);

    const huffman_node_t *node = table->nodes;
    while (node->left != -1) {
        bit = bits & 1;
        bits >>= 1;
        node = &table->nodes[bit ? node->right : node->left];
    }

    bit = bits & 1;
    *value = (bit)? -node->right : node->right;

    return SC_OK;
}
