/*
------------------------------------------------------------------------------
isaac64.h: definitions for a random number generator
Bob Jenkins, 1996, Public Domain
------------------------------------------------------------------------------
*/
#ifndef STANDARD
#include "standard.h"
#endif

#include "prng_types.h"

#ifndef ISAAC64
#define ISAAC64
#define RANDSIZL   (8)
#define RANDSIZ    (1<<RANDSIZL)

/* context of random number generator */
PRNG_STRUCT_PACK_START
typedef struct randctx {
  ub8 randcnt;
  ub8 randrsl[RANDSIZ];
  ub8 randmem[RANDSIZ];
  ub8 randa;
  ub8 randb;
  ub8 randc;
} PRNG_STRUCT_PACKED randctx;
PRNG_STRUCT_PACK_END

/*
------------------------------------------------------------------------------
 If (flag==TRUE), then use the contents of randrsl[0..255] as the seed.
------------------------------------------------------------------------------
*/
void randinit();

void isaac64();


/*
------------------------------------------------------------------------------
 Call rand() to retrieve a single 64-bit random value
------------------------------------------------------------------------------
*/
#define rand(r) \
   (!(r)->randcnt-- ? \
     (isaac64(r), (r)->randcnt=RANDSIZ-1, (r)->randrsl[(r)->randcnt]) : \
     (r)->randrsl[(r)->randcnt])

#endif  /* ISAAC64 */

