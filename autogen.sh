#!/bin/bash

autoreconf -fvi
cd src/utils/arith; sh gen_ntt.sh cpp
