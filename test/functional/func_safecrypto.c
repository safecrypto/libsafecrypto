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

#include <stdlib.h>
#include "safecrypto.h"


int main(void)
{
	UINT32 version = safecrypto_get_version();
	char *version_string = safecrypto_get_version_string();

	fprintf(stderr, "libsafecrypto v%08X (%s)\n",
		version, version_string);

	size_t i;
	fprintf(stderr, "Supported schemes:\n");
	for (i=0; i<SC_SCHEME_MAX; i++) {
		fprintf(stderr, "%2lu: %s\n", i, sc_scheme_names[i]);
	}

	return EXIT_SUCCESS;
}


