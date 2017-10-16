/* pipe.c - The pipe implementation. This is the only file that must be linked
 *          to use the pipe.
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

#include "pipe.h"

#include "safecrypto_private.h"
#include "utils/arith/sc_math.h"


/// The default initial minimum capacity of the pipe
#define DEFAULT_PIPE_MINCAP    32


//--------------------------- PRIVATE FUNCTIONS -----------------------------//

/// @brief Given the specified pipe obtain the instantaneous status
static pipe_snapshot_t create_snapshot(pipe_t *p)
{
    pipe_snapshot_t s;
    s.elem_size = p->elem_size;
    s.buffer    = p->buffer;
    s.bufend    = p->bufend;
    s.begin     = p->begin;
    s.end       = p->end;
    return s;
}

/// @brief Determine how many bytes are available in a pipe
static inline size_t capacity(pipe_snapshot_t s)
{
    return s.bufend - s.buffer - s.elem_size;
}

/// @brief Determine how many bytes in a pipe are currently used to store data
static inline size_t bytes_in_use(pipe_snapshot_t s)
{
    return ((s.begin >= s.end)?
              ((s.end - s.buffer) + (s.bufend - s.begin))
            : (s.end - s.begin))
        - s.elem_size;
}

/// @brief Check a pipe to ensure the buffer parameters are valid
static inline SINT32 check_invariants(pipe_t *p)
{
    if (NULL == p) return SC_FUNC_FAILURE;

    if (NULL == p->buffer)
    {
        if (0 != p->consumer_refcount) return SC_FUNC_FAILURE;
    }
    else
    {
        if (0 == p->consumer_refcount) return SC_FUNC_FAILURE;
    }

    pipe_snapshot_t s = create_snapshot(p);

    if (NULL == s.begin) return SC_FUNC_FAILURE;
    if (NULL == s.end) return SC_FUNC_FAILURE;
    if (NULL == s.bufend) return SC_FUNC_FAILURE;

    if (0 == p->elem_size) return SC_FUNC_FAILURE;

    if (bytes_in_use(s) > capacity(s)) return SC_FUNC_FAILURE;

    if(s.begin == s.end) {
        if (bytes_in_use(s) != capacity(s)) return SC_FUNC_FAILURE;
    }

    return SC_FUNC_SUCCESS;
}

/// @brief Given a pipe pointer, lock all mutexes in a prescribed order
static inline SINT32 lock_pipe(pipe_t *p)
{
    utils_threading()->mtx_lock(p->end_lock);
    utils_threading()->mtx_lock(p->begin_lock);
    return check_invariants(p);
}

/// @brief Given a pipe pointer, unlock all mutexes in a prescribed order
static inline SINT32 unlock_pipe(pipe_t *p)
{
    if (SC_FUNC_FAILURE == check_invariants(p)) {
        return SC_FUNC_FAILURE;
    }
    utils_threading()->mtx_unlock(p->begin_lock);
    utils_threading()->mtx_unlock(p->end_lock);
    return SC_FUNC_SUCCESS;
}

/// @brief Return the given value rounded up the nearest power of 2.
static size_t next_pow2(size_t n)
{
    return 1 << sc_ceil_log2_32(n);
}

/// @brief Returns a wrapped pointer
static inline UINT8* wrap_ptr(UINT8* buffer,
                              UINT8* p,
                              UINT8* bufend)
{
    if (p >= bufend) {
        size_t diff = p - bufend;
        return buffer + diff;
    }
    else {
        return p;
    }
}

/// @brief Block until bytes are buffered in the pipe
static pipe_snapshot_t wait_for_elements(pipe_t *p)
{
    pipe_snapshot_t s = create_snapshot(p);
    size_t bytes = bytes_in_use(s);
    size_t producer_refcount = p->producer_refcount;

    while (0 == bytes && producer_refcount > 0) {
        utils_threading()->cond_wait(p->just_pushed, p->begin_lock);

        s = create_snapshot(p);
        bytes = bytes_in_use(s);
        producer_refcount = p->producer_refcount;
    }

    return s;
}

/// @brief Runs a memcpy, then returns the end of the range copied.
/// Has identical functionality as mempcpy, but is portable.
static inline void* offset_memcpy(void * restrict dest,
                                  const void * restrict src,
                                  size_t n)
{
    SC_MEMCOPY(dest, src, n);
    return (UINT8*) dest + n;
}

/// @brief Resizes the given pipe buffer (if necessary) and returns a snapshot.
static pipe_snapshot_t resize_buffer(pipe_t *p, size_t cap)
{
    pipe_snapshot_t s;
    check_invariants(p);

    size_t elem_size = p->elem_size;
    size_t max_cap   = p->max_cap;
    size_t min_cap   = p->min_cap;

    // Apply limits to the new buffer size
    if (cap >= max_cap) {
        cap = max_cap;
    }
    s = create_snapshot(p);
    if (cap <= min_cap) {
        return s;
    }

    // Create a new buffer, copy the data and destroy the original
    UINT8 *buffer = SC_MALLOC(cap + elem_size);
    p->end = buffer;
    if (s.begin >= s.end)
    {
        p->end = offset_memcpy(p->end, s.begin, s.bufend - s.begin);
        p->end = offset_memcpy(p->end, s.buffer, s.end - s.buffer);
    }
    else
    {
        p->end = offset_memcpy(p->end, s.begin, s.end - s.begin);
    }
    SC_FREE(p->buffer, 0);//elem_size * min_cap);
    p->begin  = buffer;
    p->buffer = buffer;
    p->bufend = buffer + cap + elem_size;

    check_invariants(p);

    return create_snapshot(p);
}

/// @brief Reduce the buffer size if a quarter or less of the buffer is used.
static void trim_buffer(pipe_t *p, pipe_snapshot_t s)
{
    size_t cap = capacity(s);

    if (bytes_in_use(s) > (cap >> 2)) {
        utils_threading()->mtx_unlock(p->begin_lock);
        return;
    }

    utils_threading()->mtx_unlock(p->begin_lock);
    utils_threading()->mtx_lock(p->end_lock);
    utils_threading()->mtx_lock(p->begin_lock);

    s = create_snapshot(p);
    cap = capacity(s);
    if (bytes_in_use(s) <= (cap >> 2)) {
        resize_buffer(p, cap >> 1);
    }

    utils_threading()->mtx_unlock(p->begin_lock);
    utils_threading()->mtx_unlock(p->end_lock);
}

/// @brief Clear data from a buffer
static pipe_snapshot_t clear_without_locking(pipe_snapshot_t s, size_t bytes_to_clear, UINT8 **begin)
{
    size_t avail_bytes = (size_t)(s.bufend - s.begin - s.elem_size);
    size_t num_bytes   = (bytes_to_clear < avail_bytes)? bytes_to_clear : avail_bytes;

    // Clear all requested data or all available data in a wrapped buffer
    bytes_to_clear -= num_bytes;
    s.begin += num_bytes;
    s.begin = wrap_ptr(s.buffer, s.begin, s.bufend);

    // Now clear the remaining data
    if (bytes_to_clear > 0) {
        s.begin += s.elem_size;
        s.begin = wrap_ptr(s.buffer, s.begin, s.bufend);

        s.begin += bytes_to_clear;
        s.begin = wrap_ptr(s.buffer, s.begin, s.bufend);

        s.begin -= s.elem_size;
        s.begin = wrap_ptr(s.buffer, s.begin, s.bufend);
    }

    *begin = s.begin;
    return s;
}

/// @brief Free memory resources associated with a buffer
static void deallocate(pipe_t *p)
{
    //size_t cap   = p->elem_size * p->min_cap;

    utils_threading()->mtx_destroy(&p->begin_lock);
    utils_threading()->mtx_destroy(&p->end_lock);
    utils_threading()->cond_destroy(&p->just_pushed);
    utils_threading()->cond_destroy(&p->just_pulled);
    if (p->buffer) SC_FREE(p->buffer, 0);//cap);
    if (p) SC_FREE(p, sizeof(pipe_t));
}

/// @brief Block until the specified capacity is available
static pipe_snapshot_t wait_for_space(pipe_t *p, size_t *max_cap)
{
    pipe_snapshot_t s = create_snapshot(p);
    size_t bytes = bytes_in_use(s);
    size_t consumer_refcount = p->consumer_refcount;

    *max_cap = p->max_cap;

    // Loop until the used bytes are not equal to the maximum capacity
    // of the buffer OR the consumer reference count equals 0.
    while (bytes == *max_cap && consumer_refcount > 0) {
        utils_threading()->cond_wait(p->just_pulled, p->end_lock);

        s = create_snapshot(p);
        bytes = bytes_in_use(s);
        consumer_refcount = p->consumer_refcount;
        *max_cap = p->max_cap;
    }

    return s;
}

/// @brief Push elements into the buffer according to byte size
static UINT8 * push_elems(pipe_snapshot_t s, const void *restrict elems, size_t num_bytes)
{
    if (s.begin < s.end) {
        size_t bytes_avail = (size_t) (s.bufend - s.end);
        size_t at_end = (num_bytes < bytes_avail)? num_bytes : bytes_avail;
        s.end = offset_memcpy(s.end, elems, at_end);
        elems = (const UINT8*) elems + at_end;
        num_bytes -= at_end;
    }

    if (num_bytes) {
        s.end = wrap_ptr(s.buffer, s.end, s.bufend);
        s.end = offset_memcpy(s.end, elems, num_bytes);
    }

    s.end = wrap_ptr(s.buffer, s.end, s.bufend);

    return s.end;
}

/// @brief Push elements into the buffer according to a count
static SINT32 push(pipe_t* p, const void* restrict elems, size_t count)
{
    size_t max_cap, pushed = 0;
    size_t elem_size = p->elem_size;
    size_t bytes;
    size_t cap;
    pipe_snapshot_t s;

    if (0 == count || NULL == elems) {
        return SC_FUNC_FAILURE;
    }

    utils_threading()->mtx_lock(p->end_lock);
    s = wait_for_space(p, &max_cap);

    if (0 == p->consumer_refcount) {
        utils_threading()->mtx_unlock(p->end_lock);
        return SC_FUNC_FAILURE;
    }

    // Ensure that data is available in the buffer
    bytes = count + bytes_in_use(s);
    cap   = capacity(s);
    if (bytes > cap) {
        utils_threading()->mtx_lock(p->begin_lock);
        s     = create_snapshot(p);
        bytes = count + bytes_in_use(s);
        if (bytes > cap) {
            size_t elems_needed = bytes / elem_size;
            s = resize_buffer(p, next_pow2(elems_needed+1)*elem_size);
        }
        utils_threading()->mtx_unlock(p->begin_lock);
    }

    // Push data into the buffer and update the pointers
    pushed = max_cap - bytes_in_use(s);
    if (count < pushed) {
        pushed = count;
    }
    p->end = push_elems(s, elems, pushed);

    utils_threading()->mtx_unlock(p->end_lock);

    // Signal if we've pushed one element, broadcast otherwise
    if (pushed == elem_size) {
        utils_threading()->cond_signal(p->just_pushed);
    }
    else {
        utils_threading()->cond_broadcast(p->just_pushed);
    }

    // Call this function again if we have more data to push
    count -= pushed;
    if (count) {
        push(p, (const UINT8*)elems + pushed, count);
    }

    return SC_FUNC_SUCCESS;
}

/// @brief Pull bytes from the buffer without uses guards
static pipe_snapshot_t pull_without_locking(pipe_snapshot_t s, void * restrict target,
    size_t bytes_to_copy, UINT8 **begin)
{
    size_t avail_bytes = (size_t)(s.bufend - s.begin - s.elem_size);
    size_t num_bytes   = (bytes_to_copy < avail_bytes)? bytes_to_copy : avail_bytes;

    // Copy all requested data or all available data in a wrapped buffer
    target = offset_memcpy(target, s.begin + s.elem_size, num_bytes);
    bytes_to_copy -= num_bytes;
    s.begin += num_bytes;
    s.begin = wrap_ptr(s.buffer, s.begin, s.bufend);

    // Now copy the remaining data
    if (bytes_to_copy > 0) {
        s.begin += s.elem_size;
        s.begin = wrap_ptr(s.buffer, s.begin, s.bufend);

        SC_MEMCOPY(target, s.begin, bytes_to_copy);

        s.begin += bytes_to_copy;
        s.begin = wrap_ptr(s.buffer, s.begin, s.bufend);

        s.begin -= s.elem_size;
        s.begin = wrap_ptr(s.buffer, s.begin, s.bufend);
    }

    *begin = s.begin;
    return s;
}

/// @brief Pull a requested number of bytes from the buffer
static size_t pull(pipe_t *p, void *target, size_t requested)
{
    size_t pulled = 0;

    // Quickly return if no data is requested
    if (0 == requested) {
        return 0;
    }

    utils_threading()->mtx_lock(p->begin_lock);
    
    // Wait until the required data is available
    pipe_snapshot_t s = wait_for_elements(p);
    size_t bytes_used = bytes_in_use(s);
    if (0 == bytes_used) {
        utils_threading()->mtx_unlock(p->begin_lock);
        return 0;
    }

    // Retrieve the required data
    check_invariants(p);
    pulled = (requested < bytes_used)? requested : bytes_used;
    s = pull_without_locking(s, target, pulled, &p->begin);
    check_invariants(p);

    // NOTE: trim_buffer() will unlock begin_lock
    trim_buffer(p, s);

    // If a single element is pulled signal the just_pulled condition variable,
    // otherwise broadcast.
    if (pulled == p->elem_size) {
        utils_threading()->cond_signal(p->just_pulled);
    }
    else {
        utils_threading()->cond_broadcast(p->just_pulled);
    }

    return pulled;
}


//--------------------------- PUBLIC FUNCTIONS ------------------------------//

pipe_t * pipe_create(size_t elem_size, size_t original_limit)
{
    // Return a NULL pointer if the user tries to create a 0 length buffer.
    if (0 == elem_size) {
        return NULL;
    }

    // Set the current buffer capacities
    size_t cap   = elem_size * DEFAULT_PIPE_MINCAP;
    size_t limit = (original_limit + 1) * elem_size;

    // Create the pipe structure
    pipe_t *p = SC_MALLOC(sizeof(pipe_t));
    if (NULL == p) {
        return NULL;
    }

    // Allocate memory for the buffer
    UINT8 *buffer = SC_MALLOC(cap);
    if (NULL == buffer) {
        SC_FREE(p, sizeof(pipe_t));
        return NULL;
    }

    // Configure the pipe structure
    p->elem_size = elem_size;
    p->min_cap   = cap;
    p->max_cap   = original_limit? next_pow2((limit > cap)? limit : cap) : ~(size_t)0;
    p->buffer    = buffer;
    p->bufend    = buffer + cap;
    p->begin     = buffer;
    p->end       = buffer + elem_size;

    // Initialise the producer and consumer reference counters to 1 to signify
    // that a 'parent' pipe has been instantiated.
    p->producer_refcount = 1;
    p->consumer_refcount = 1;

    // Create the mutexes used to lock access to the buffer interfaces
    p->begin_lock = utils_threading()->mtx_create();
    p->end_lock   = utils_threading()->mtx_create();

    // Create the condition variables used to control the buffer interfaces
    p->just_pushed = utils_threading()->cond_create();
    p->just_pulled = utils_threading()->cond_create();

    return p;
}

pipe_producer_t * pipe_producer_create(pipe_t *p)
{
    // Return a pointer to the existing producer pipe and
    // increase the reference count.
    utils_threading()->mtx_lock(p->begin_lock);
    p->producer_refcount++;
    utils_threading()->mtx_unlock(p->begin_lock);
    return (pipe_producer_t*)p;
}

pipe_consumer_t * pipe_consumer_create(pipe_t *p)
{
    // Return a pointer to the existing consumer pipe and
    // increase the reference count.
    utils_threading()->mtx_lock(p->end_lock);
    p->consumer_refcount++;
    utils_threading()->mtx_unlock(p->end_lock);
    return (pipe_consumer_t*)p;
}

SINT32 pipe_destroy(pipe_t *p)
{
    size_t new_producer_refcount, new_consumer_refcount;

    if (NULL == p) {
        return SC_FUNC_FAILURE;
    }

    // Obtain the new reference counts for the pipe interfaces
    utils_threading()->mtx_lock(p->begin_lock);
    new_producer_refcount = --p->producer_refcount;
    utils_threading()->mtx_unlock(p->begin_lock);

    utils_threading()->mtx_lock(p->end_lock);
    new_consumer_refcount = --p->consumer_refcount;
    utils_threading()->mtx_unlock(p->end_lock);

    if (0 == new_consumer_refcount) {
        // If the consumer reference count reaches 0 the buffer is
        // destroyed if the producer reference count also reaches 0.
        // Otherwise the just pulled condition variable is broadcast.
        if (new_producer_refcount > 0) {
            utils_threading()->cond_broadcast(p->just_pulled);
        }
        else {
            deallocate(p);
        }
    }
    else if (0 == new_producer_refcount) {
        utils_threading()->cond_broadcast(p->just_pushed);
    }

    return SC_FUNC_SUCCESS;
}

SINT32 pipe_producer_destroy(pipe_producer_t *producer)
{
    size_t new_producer_refcount;

    if (NULL == producer) {
        return SC_FUNC_FAILURE;
    }

    pipe_t *p = (pipe_t*) producer;

    // Obtain the new reference count for the producer pipe interface
    utils_threading()->mtx_lock(p->begin_lock);
    new_producer_refcount = --p->producer_refcount;
    utils_threading()->mtx_unlock(p->begin_lock);

    if (0 == new_producer_refcount) {
        // If the producer reference count reaches 0 the buffer is
        // destroyed if the consumer reference count also reaches 0.
        // Otherwise the just pushed condition variable is broadcast.
        size_t consumer_refcount;
        utils_threading()->mtx_lock(p->end_lock);
        consumer_refcount = p->consumer_refcount;
        utils_threading()->mtx_unlock(p->end_lock);

        if (consumer_refcount > 0) {
            utils_threading()->cond_broadcast(p->just_pushed);
        }
        else {
            deallocate(p);
        }
    }

    return SC_FUNC_SUCCESS;
}

SINT32 pipe_consumer_destroy(pipe_consumer_t *consumer)
{
    size_t new_consumer_refcount;

    if (NULL == consumer) {
        return SC_FUNC_FAILURE;
    }

    pipe_t *p = (pipe_t*) consumer;

    // Obtain the new reference counts for the consumer pipe interface
    utils_threading()->mtx_lock(p->end_lock);
    new_consumer_refcount = --p->consumer_refcount;
    utils_threading()->mtx_unlock(p->end_lock);

    if (0 == new_consumer_refcount) {
        // If the consumer reference count reaches 0 the buffer is
        // destroyed if the producer reference count also reaches 0.
        // Otherwise the just pulled condition variable is broadcast.
        size_t producer_refcount;
        utils_threading()->mtx_lock(p->begin_lock);
        producer_refcount = p->producer_refcount;
        utils_threading()->mtx_unlock(p->begin_lock);

        if (producer_refcount > 0) {
            utils_threading()->cond_broadcast(p->just_pulled);
        }
        else {
            deallocate(p);
        }
    }

    return SC_FUNC_SUCCESS;
}

SINT32 pipe_clear(pipe_t *p)
{
    utils_threading()->mtx_lock(p->begin_lock);
    
    pipe_snapshot_t s = create_snapshot(p);
    size_t bytes_used = bytes_in_use(s);
    if (0 == bytes_used) {
        // Fast exit if the pipe is empty
        utils_threading()->mtx_unlock(p->begin_lock);
        return SC_FUNC_SUCCESS;
    }

    // Clear the buffer and resize it if necessary
    check_invariants(p);
    s = clear_without_locking(s, bytes_used, &p->begin);
    check_invariants(p);

    // NOTE: trim_buffer() will unlock begin_lock
    trim_buffer(p, s);

    // Signal if we've cleared one element, broadcast otherwise
    if (bytes_used == p->elem_size) {
        utils_threading()->cond_signal(p->just_pulled);
    }
    else {
        utils_threading()->cond_broadcast(p->just_pulled);
    }

    return SC_FUNC_SUCCESS;
}

SINT32 pipe_push(pipe_producer_t* p, const void* restrict elems, size_t count)
{
    // Convert elements to bytes and call the generic push function.
    pipe_t *pipe = (pipe_t*) p;
    count *= pipe->elem_size;
    return push(pipe, elems, count);
}

size_t pipe_pull(pipe_consumer_t *p, void *target, size_t count)
{
    pipe_t* pipe = (pipe_t*) p;
    size_t elem_size = pipe->elem_size;
    size_t bytes_left  = count * elem_size;
    size_t bytes_pulled = 0;
    size_t ret = -1;

    // While we're able to and the requested number of bytes
    // has not been retrieved we will continue to pull data and copy it
    // into the user's target buffer.
    do {
        ret = pull(pipe, target, bytes_left);
        target = (void*)((UINT8*)target + ret);
        bytes_pulled += ret;
        bytes_left   -= ret;
    } while(0 != ret && bytes_left);

    // Return the number of elements retrieved.
    return bytes_pulled / elem_size;
}

size_t pipe_pull_nonblocking(pipe_consumer_t *p, void *target, size_t count)
{
    // Pull what we can and then quickly return.
    pipe_t *pipe = (pipe_t*) p;
    size_t elem_size = pipe->elem_size;
    size_t pulled_size = pull(pipe, target, count * elem_size);
    return pulled_size / elem_size;
}

void pipe_reserve(pipe_generic_t *gen, size_t count)
{
    // Obtain the pipe pointer
    pipe_t *p = (pipe_t*) gen;

    // Modify the element count to become a byte count
    count *= p->elem_size;

    // Ensure that the reserved size can be no less the defined
    // minimum capacity.
    if (0 == count) {
        count = DEFAULT_PIPE_MINCAP;
    }

    size_t max_cap = p->max_cap;

    // Obtain control of the pipe and resize the buffer, ensuring that
    // the data is not erased.
    lock_pipe(p);
    do {
        if (count <= bytes_in_use(create_snapshot(p)))
            break;
    
        p->min_cap = (count < max_cap)? count : max_cap;
        resize_buffer(p, count);
    } while (0);
    unlock_pipe(p);
}

