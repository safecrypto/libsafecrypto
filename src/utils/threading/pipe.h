/* pipe.h - The public pipe interface. This is the only file that must be
 *          included to begin using the pipe.
 *
 * The MIT License
 * Copyright (c) 2011 Clark Gaebel <cg.wowus.cg@gmail.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */

/* The pipeline implementation is a port of Clark gaebel's pipe
 * See "https://github.com/cgaebel/pipe"
 * It has been modified to use the threading functions used elsewhere within
 * the SAFEcrypto library.
 *
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */

#pragma once

#include "safecrypto_types.h"
#include "utils/threading/threading.h"


SC_STRUCT_PACK_START
typedef struct pipe_t {
    size_t elem_size;  // The size of each element. This is read-only and
                       // therefore does not need to be locked to read.
    size_t min_cap;    // The smallest sane capacity before the buffer refuses
                       // to shrink because it would just end up growing again.
                       // To modify this variable, you must lock the whole pipe.
    size_t max_cap;    // The maximum capacity of the pipe before push requests
                       // are blocked. To read or write to this variable, you
                       // must hold 'end_lock'.

    UINT8 *buffer;     // The internal buffer, holding the enqueued elements.
                       // to modify this variable, you must lock the whole pipe.
    UINT8 *bufend;     // One past the end of the buffer, so that the actual
                       // elements are stored in in interval [buffer, bufend).
    UINT8 *begin;      // Always points to the sentinel element. `begin + elem_size`
                       // points to the left-most element in the pipe.
                       // To modify this variable, you must lock begin_lock.
    UINT8 *end;        // Always points past the right-most element in the pipe.
                       // To modify this variable, you must lock end_lock.

    // The number of producers/consumers in the pipe.
    size_t producer_refcount; // Guarded by begin_lock.
    size_t consumer_refcount; // Guarded by end_lock.

    // To lock the pipe, call lock_pipe. Depending on what you modify, you
    // may be able to get away with only locking one of them.
    sc_mutex_t *begin_lock;
    sc_mutex_t *end_lock;

    sc_cond_t *just_pushed; // Signaled immediately after a push.
    sc_cond_t *just_pulled; // Signaled immediately after a pull.
} SC_STRUCT_PACKED pipe_t;
SC_STRUCT_PACK_END

SC_STRUCT_PACK_START
typedef struct pipe_snapshot_t {
    size_t elem_size;  // The size of each element. This is read-only and
                       // therefore does not need to be locked to read.
    UINT8 *buffer;     // The internal buffer, holding the enqueued elements.
                       // to modify this variable, you must lock the whole pipe.
    UINT8 *bufend;     // One past the end of the buffer, so that the actual
                       // elements are stored in in interval [buffer, bufend).
    UINT8 *begin;      // Always points to the sentinel element. `begin + elem_size`
                       // points to the left-most element in the pipe.
                       // To modify this variable, you must lock begin_lock.
    UINT8 *end;        // Always points past the right-most element in the pipe.
                       // To modify this variable, you must lock end_lock.
} SC_STRUCT_PACKED pipe_snapshot_t;
SC_STRUCT_PACK_END

/// Alternative typedef's of pipe_t for readability and clarity
/// @{
typedef struct pipe_producer_t pipe_producer_t;
typedef struct pipe_consumer_t pipe_consumer_t;
typedef struct pipe_generic_t pipe_generic_t;
/// @}

/// Create the pipe structure and allocate memory to the buffer. A minimal
/// buffer capacity is enforced according to the number of elements specified
/// by original_limit.
pipe_t * pipe_create(size_t elem_size, size_t original_limit);

/// Returns a pipe_producer structure cast from the input pipe and
/// reference counted.
pipe_producer_t * pipe_producer_create(pipe_t* p);

/// Returns a pipe_consumer structure cast from the input pipe and
/// reference counted.
pipe_consumer_t * pipe_consumer_create(pipe_t* p);

/// Deallocate resources associated with a pipe structure
SINT32 pipe_destroy(pipe_t *p);

/// Deallocate resources associated with a producer pipe structure
SINT32 pipe_producer_destroy(pipe_producer_t *producer);

/// Deallocate resources associated with a consumer pipe structure
SINT32 pipe_consumer_destroy(pipe_consumer_t *consumer);

/// Clear the pipe of all buffered data
SINT32 pipe_clear(pipe_t *p);

/// Push a specified number of elements into the pipe
SINT32 pipe_push(pipe_producer_t* p, const void* restrict elems, size_t count);

/// Pull the specified number of elements from the pipe
size_t pipe_pull(pipe_consumer_t* p, void* target, size_t count);

/// Pull the specified number of elements from the pipe if possible
size_t pipe_pull_nonblocking(pipe_consumer_t* p, void* target, size_t count);

/// Modify the minimum capacity of the pipe
void pipe_reserve(pipe_generic_t* gen, size_t count);
