![Alt text](https://www.safecrypto.eu/wp-content/uploads/2015/02/Header.jpg)

# SAFEcrypto

**S**ecure **A**rchitectures of **F**uture **E**merging **Cryptography**

SAFEcrypto will provide a new generation of practical, robust, and physically
secure post-quantum cryptographic functions. Work Package 6 will develop a
suite of software routines to implement the lattice-based constructions identified
in Work Package 4 of the SAFEcrypto project, whilst providing cryptographic
primitives for use in the demonstrations developed in Work Package 9.

The following schemes are currently supported...

Signatures:
- BLISS-B
- Dilithium / Dilithium-G
- ENS
- DLP
- Ring-TESLA
- Falcon (this branch only)
             
KEM:
- ENS
- Kyber
             
Encryption:
- RLWE
- Kyber
             
IBE:
- DLP


# Directory Structure

* docs             - All documentation relating to the SAFEcrypto software library
* examples         - Example applications demonstrating the library's capabilities
* include          - Header files to be distributed with the shared/static library
* src              - All software code relating to the library itself
  - schemes        - LBC cryptographic algorithms
  - utils          - Common shared mathemtical and cryptographic functions
  - unit           - Unit Tests
* test             - Test software
  - functional     - Functional Tests
  - kat            - Known Answer Tests
* LICENSE          - Software licensing notice
* README           - This file


---
# Copyright

Copyright (C) Queen’s University Belfast, ECIT, 2016, 2017



---
# Dependencies

autotools, autoconf, autoconf-archive, automake, libtool, doxygen, texlive,
pkg-config, check-devel, subunit-devel

Optionally: gmp, mpfr

Dockerfile available in master branch

---
# Installation

If building from a cloned version control repository (rather than a source
code distribution) the user must configure autotools by running the 
following script:

    ./autogen.sh

Generate the required Makefile's for your environment using the folowing
command:

    ./configure

If the library and associated software is to be created for development purposes
or debugging then the configure command should be passed the relevant arguments:

    ./configure CPPFLAGS=-DDEBUG CFLAGS="-g -O0"

The generated Makefile at the root level must then be executed to build the
SAFEcrypto software library and all associated applications. A number of
automated tests are executed as part of the automated build to ensure that the
software has been successfuly built on the target system.

    make

If the user wishes to generate the reference documentation in PDF and html
format then the following make target should be executed:

    make doxygen-doc

In order to install the generated libraries onto the system the user must
execute the following command:

    make install


---
# Running Tests

The source code for the test functions can be found in ./test/functional. Different variants of the schemes are included, e.g. func_alg_dlp_sig.c refers to the DLP signature scheme, whilst func_alg_dlp_sig_recovery.c refers to the variant with the message recovery property. Test files for components such as sampling and NTT are also present. To run the FALCON signature scheme:

    ./func_alg_function

Within the test files, parameter sets can be modified (specified by the i index) and flags can be set to specify sampling techniques used or countermeasures switched on. The list of available flags is found in include/safecrypto.h.

---
# Licensing

The MIT License applies to this software, please refer to the LICENSE file
in the root directory for details.

Portions of this Software utilise open source software. No open source software 
used in libsafecrypto has been endorsed by any of the authors. We would like to 
thank the following for their contribution to the open source community. Please 
refer to the associated src/utils/third_party directory for the
relevant source code.


---
## AES - src/utils/third_party/aes

    Copyright (c) 1998-2013, Brian Gladman, Worcester, UK. All rights reserved.
    The redistribution and use of this software (with or without changes)
    is allowed without the payment of fees or royalties provided that:

    source code distributions include the above copyright notice, this
    list of conditions and the following disclaimer;

    binary distributions include the above copyright notice, this list
    of conditions and the following disclaimer in their documentation.

    This software is provided 'as is' with no explicit or implied warranties
    in respect of its operation, including, but not limited to, correctness
    and fitness for purpose.

---
## BLAKE2 - src/utils/crypto/blake2

     Written in 2012 by Samuel Neves <sneves@dei.uc.pt>

     To the extent possible under law, the author(s) have dedicated all copyright
     and related and neighboring rights to this software to the public domain
     worldwide. This software is distributed without any warranty.

     You should have received a copy of the CC0 Public Domain Dedication along 
     with this software. If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.

---
## CHACHA20 - src/utils/crypto/chacha

    By Emill, 2016, Public Domain

---
## ISAAC - src/utils/crypto/isaac

    By Bob Jenkins, 1996, Public Domain

---
## Mersenne Twister - src/utils/mersenne_twister

    A C-program for MT19937, with initialization improved 2002/1/26.
    Coded by Takuji Nishimura and Makoto Matsumoto.

    Before using, initialize the state by using init_genrand(seed)  
    or init_by_array(init_key, key_length).

    Copyright (C) 1997 - 2002, Makoto Matsumoto and Takuji Nishimura,
    All rights reserved.                          

    Redistribution and use in source and binary forms, with or without
    modification, are permitted provided that the following conditions
    are met:

     1. Redistributions of source code must retain the above copyright
        notice, this list of conditions and the following disclaimer.

     2. Redistributions in binary form must reproduce the above copyright
        notice, this list of conditions and the following disclaimer in the
        documentation and/or other materials provided with the distribution.

     3. The names of its contributors may not be used to endorse or promote 
        products derived from this software without specific prior written 
        permission.

    THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
    "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
    LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
    A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR
    CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
    EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
    PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
    PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
    LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
    NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
    SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


    Any feedback is very welcome.
    http://www.math.sci.hiroshima-u.ac.jp/~m-mat/MT/emt.html
    email: m-mat @ math.sci.hiroshima-u.ac.jp (remove space)
   
---
## SALSA20 - src/utils/crypto/salsa

    D. J. Bernstein, Public Domain

---
## SHA-2 - src/utils/crypto/sha2

    Copyright (c) 2002, Dr Brian Gladman, Worcester, UK.   All rights reserved.

    LICENSE TERMS

    The free distribution and use of this software in both source and binary
    form is allowed (with or without changes) provided that:

     1. distributions of this source code include the above copyright
        notice, this list of conditions and the following disclaimer;

     2. distributions in binary form include the above copyright
        notice, this list of conditions and the following disclaimer
        in the documentation and/or other associated materials;

     3. the copyright holder's name is not used to endorse products
        built using this software without specific written permission.

    ALTERNATIVELY, provided that this notice is retained in full, this product
    may be distributed under the terms of the GNU General Public License (GPL),
    in which case the provisions of the GPL apply INSTEAD OF those given above.

    DISCLAIMER
  
    This software is provided 'as is' with no explicit or implied warranties
    in respect of its properties, including, but not limited to, correctness
    and/or fitness for purpose.

---
## SHA-3 - src/utils/crypto/sha3

    19-Nov-11  Markku-Juhani O. Saarinen <mjos@iki.fi>

---
## Whirlpool - src/utils/crypto/whirlpool

    Copyright: 2009-2012 Aleksey Kravchenko <rhash.admin@gmail.com>
   
    Permission is hereby granted,  free of charge,  to any person  obtaining a
    copy of this software and associated documentation files (the "Software"),
    to deal in the Software without restriction,  including without limitation
    the rights to  use, copy, modify,  merge, publish, distribute, sublicense,
    and/or sell copies  of  the Software,  and to permit  persons  to whom the
    Software is furnished to do so.
   
    This program  is  distributed  in  the  hope  that it will be usefu,  but
    WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
    or FITNESS FOR A PARTICULAR PURPOSE.  Use this program  at  your own risk!


# Bug Reporting, Feature Requests And Dev Community


---
# Contact Information


---
# Legal Notices

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS 
FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN 
AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION 
WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE

