/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

/**
 * @file
 * This is a simplified version of the error queue used by OpenSSL. Error
 * messages can be added to the queue until it reaches its maximum depth,
 * at this point the queue is full and new messages added to it will be
 * silently discarded.
 *
 * @author n.smyth@qub.ac.uk
 * @date 10 Aug 2016
 * @brief Header file for the error queue used by the SAFEcrypto SW library.
 *
 * Git commit information:
 *   Author: $SC_AUTHOR$
 *   Date:   $SC_DATE$
 *   Branch: $SC_BRANCH$
 *   Id:     $SC_IDENT$
 */


#pragma once

#include <stdint.h>
#include "safecrypto_private.h"


/// A macro for users to use when they want to log an error.
#define SC_LOG_ERROR(sc,e)   if (sc != NULL) { add_err_code((sc->error_queue), (e), __FILE__, __LINE__); }

/// The maximum number of error messages in the queue
#define MAX_ERROR_MESSAGES    8


/// A struct defining an error message that is buffered in a queue
SC_STRUCT_PACK_START
typedef struct err_msg {
    SINT32 error;
    char file[SC_MAX_FILENAME_LEN];
    SINT32 line;
} SC_STRUCT_PACKED err_msg_t;
SC_STRUCT_PACK_END

SC_STRUCT_PACK_START
typedef struct err_ctrl {
    /// An instance of the error message queue
    err_msg_t error_queue[MAX_ERROR_MESSAGES];

    SINT32 wr_index;  /// The write index counter
    SINT32 rd_index;  /// The read index counter
    SINT32 level;     /// The error queue depth counter
} SC_STRUCT_PACKED err_ctrl_t;
SC_STRUCT_PACK_END


/// Error queue creation function
err_ctrl_t *err_create(void);

/// Free resources associated with the specified error queue
/// @return A standard SAFEcrypto function return code
SINT32 err_destroy(err_ctrl_t **ctrl);


/** Get the debug verbosity
 *  @param ctrl A pointer to the error_ctrl_t instance
 *  @param error The error code
 *  @param file Name of the file producing the error
 *  @param line The line number of the call to add_err_code()
 */
void add_err_code(err_ctrl_t *ctrl, SINT32 error, const char *file, SINT32 line);

/// Get the error code and remove the error message from the queue.
UINT32 err_get_error(err_ctrl_t *ctrl);

/// Get the error code but do NOT remove the error message from the queue.
UINT32 err_peek_error(err_ctrl_t *ctrl);

/// Get the error code, file and line number and remove from the queue
UINT32 err_get_error_line(err_ctrl_t *ctrl, const char **file, SINT32 *line);

/**
 * Get the error code, file and line number but do NOT remove the
 * error message from the queue.
 */
UINT32 err_peek_error_line(err_ctrl_t *ctrl, const char **file, SINT32 *line);

/**
 * Clear all error messages in the queue.
 */
void err_clear_error(err_ctrl_t *ctrl);


