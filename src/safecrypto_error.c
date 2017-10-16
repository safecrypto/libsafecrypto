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

#include "safecrypto_error.h"
#include "safecrypto.h"
#include "safecrypto_private.h"

#include <string.h>


/*
 * Error messages are buffered in a queue of fixed maximum length. If the error
 * queue is full when a new error message is added that new message will be
 * discarded,
 */


err_ctrl_t *err_create(void)
{
	err_ctrl_t *p = SC_MALLOC(sizeof(err_ctrl_t));

	// Conditionally initialise the struct if pointer is non NULL
	if (p) {
		p->wr_index = 0;
		p->rd_index = 0;
		p->level = 0;
	}
	return p;
}

SINT32 err_destroy(err_ctrl_t **ctrl)
{
	if (ctrl) {
		SC_FREE(*ctrl, sizeof(err_ctrl_t));
		return SC_FUNC_SUCCESS;
	}
	return SC_FUNC_FAILURE;
}

void add_err_code(err_ctrl_t *ctrl, SINT32 error, const char *file, SINT32 line)
{
	if (ctrl->level == MAX_ERROR_MESSAGES)
		return;
	if (error < SC_OK || error >= SC_NUM_ERROR_CODES)
		return;
	if (line < 0)
		return;

	// Copy the error message to the buffer, truncating the filename if necessary
	if (file) {
		ctrl->error_queue[ctrl->wr_index].error = error;
		strncpy(ctrl->error_queue[ctrl->wr_index].file, file, SC_MAX_FILENAME_LEN - 1);
		ctrl->error_queue[ctrl->wr_index].file[SC_MAX_FILENAME_LEN - 1] = '\0';
		ctrl->error_queue[ctrl->wr_index].line = line;

        // Ensure that the write index wraps around
		ctrl->wr_index++;
		if (ctrl->wr_index == MAX_ERROR_MESSAGES) ctrl->wr_index = 0;

		// The error level can never be incremented beyond MAX_ERROR_MESSAGES due
		// to the above out-of-bounds check
		ctrl->level++;
	}
}

UINT32 err_get_error(err_ctrl_t *ctrl)
{
	UINT32 error = SC_GETERR_NULL_POINTER;
    if (ctrl) {
    	if (ctrl->level == 0)
    		return SC_OK;
    
    	error = ctrl->error_queue[ctrl->rd_index].error;
    
    	ctrl->level--;
    	ctrl->rd_index++;
    	if (ctrl->rd_index == MAX_ERROR_MESSAGES) ctrl->rd_index = 0;
    }

	return error;
}

UINT32 err_peek_error(err_ctrl_t *ctrl)
{
	if (ctrl == NULL)
		return SC_GETERR_NULL_POINTER;
	if (ctrl->level == 0)
		return SC_OK;

	return ctrl->error_queue[ctrl->rd_index].error;
}

UINT32 err_get_error_line(err_ctrl_t *ctrl, const char **file, SINT32 *line)
{
	UINT32 error;
	if (ctrl == NULL)
		return SC_GETERR_NULL_POINTER;
	if (ctrl->level == 0)
		return SC_OK;

	error = ctrl->error_queue[ctrl->rd_index].error;
	*file = ctrl->error_queue[ctrl->rd_index].file;
	*line = ctrl->error_queue[ctrl->rd_index].line;

	ctrl->level--;
	ctrl->rd_index++;
	if (ctrl->rd_index == MAX_ERROR_MESSAGES) ctrl->rd_index = 0;

	return error;
}

UINT32 err_peek_error_line(err_ctrl_t *ctrl, const char **file, SINT32 *line)
{
	if (ctrl == NULL)
		return SC_GETERR_NULL_POINTER;
	if (ctrl->level == 0)
		return SC_OK;

	*file = ctrl->error_queue[ctrl->rd_index].file;
	*line = ctrl->error_queue[ctrl->rd_index].line;

	return ctrl->error_queue[ctrl->rd_index].error;
}

void err_clear_error(err_ctrl_t *ctrl)
{
	if (ctrl != NULL) {
	    ctrl->wr_index = 0;
	    ctrl->rd_index = 0;
	    ctrl->level    = 0;
    }
}

