#!/bin/bash
#
# The Queen's University of Belfast ECIT 2018
# This file is subject to the terms and conditions defined in
# file 'LICENSE.md', which is part of this source code package.
#
# User ID mapping reference from:
#   https://gist.github.com/renzok/29c9e5744f1dffa392cf


if [ -z "${USER}" ]; then
  echo "We need USER to be set!"; exit 100
fi

# if both not set we do not need to do anything
if [ -z "${HOST_USER_ID}" ] && [ -z "${HOST_USER_GID}" ]; then
    echo "Nothing to do here." ; exit 0
fi

# reset user_id to either new id or if empty old
USER_ID=${HOST_USER_ID:=$USER_ID}
USER_GID=${HOST_USER_GID:=$USER_GID}

# replace user/group ids
sed -i -e "s/^${USER}:\([^:]*\):[0-9]*:[0-9]*/${USER}:\1:${USER_ID}:${USER_GID}/"  /etc/passwd
sed -i -e "s/^${USER}:\([^:]*\):[0-9]*/${USER}:\1:${USER_GID}/"  /etc/group

# log in as user _without_ adapting environment
exec su "${USER}"
