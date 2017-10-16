/*****************************************************************************
 * Copyright (C) Queen's University Belfast, ECIT, 2016                      *
 *                                                                           *
 * This file is part of libsafecrypto.                                       *
 *                                                                           *
 * This file is subject to the terms and conditions defined in the file      *
 * 'LICENSE', which is part of this source code package.                     *
 *****************************************************************************/

#pragma once

#include <plugins/plugin.h>

typedef struct safecrypto_plugin_t safecrypto_plugin_t;

/**
 * Plugin implementing the SAFEcrypto post-quantum authentication schemes
 */
struct safecrypto_plugin_t {
    plugin_t plugin;
};
