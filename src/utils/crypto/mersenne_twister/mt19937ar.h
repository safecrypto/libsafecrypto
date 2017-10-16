#pragma once

/* Period parameters */  
#define N 624
#define M 397

typedef struct mt_state_t
{
    unsigned long mt[N]; /* the array for the state vector  */
    int mti; /* mti==N+1 means mt[N] is not initialized */
} mt_state_t;


extern void init_genrand(mt_state_t *ctx, unsigned long s);
extern void init_by_array(mt_state_t *ctx, unsigned long init_key[],
    int key_length);
extern unsigned long genrand_int32(mt_state_t *ctx);
