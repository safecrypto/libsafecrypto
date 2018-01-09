/*
salsa.c version 20051118
D. J. Bernstein
Public domain.
*/

#include "salsa20.h"
#include "safecrypto_private.h"

#define U8C(v) (v##U)
#define U32C(v) (v##U)
#define U8V(v) ((UINT8)(v) & U8C(0xFF))
#define U32V(v) ((UINT32)(v) & U32C(0xFFFFFFFF))
#define ROTL32(v, n) (U32V((v) << (n)) | ((v) >> (32 - (n))))
#define ROTATE(v,c) (ROTL32(v,c))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  a = PLUS(a,b); d = ROTATE(XOR(d,a),16); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c),12); \
  a = PLUS(a,b); d = ROTATE(XOR(d,a), 8); \
  c = PLUS(c,d); b = ROTATE(XOR(b,c), 7);

#define U8TO32_LITTLE_ENDIAN(p) \
  (((UINT32)((p)[0])      ) | \
   ((UINT32)((p)[1]) <<  8) | \
   ((UINT32)((p)[2]) << 16) | \
   ((UINT32)((p)[3]) << 24))

#define U32TO8_LITTLE_ENDIAN(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

// This is ASCII of "expand 32-byte k"
static const UINT32 sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

// This is ASCII of "expand 16-byte k"
static const UINT32 tau[4] = {0x61707865, 0x3120646e, 0x79622d36, 0x6b206574};

void salsa20_core(const UINT32 *input, UINT8 *output)
{
    size_t i;
    UINT32 x[16];

    SC_LITTLE_ENDIAN_32_COPY(x, 0, input, 16*sizeof(UINT32));

    for (i = 20; i > 0; i -= 2) {
        x[ 4] ^= ROTATE(x[ 0] + x[12],  7);
        x[ 8] ^= ROTATE(x[ 4] + x[ 0],  9);
        x[12] ^= ROTATE(x[ 8] + x[ 4], 13);
        x[ 0] ^= ROTATE(x[12] + x[ 8], 18);
        x[ 9] ^= ROTATE(x[ 5] + x[ 1],  7);
        x[13] ^= ROTATE(x[ 9] + x[ 5],  9);
        x[ 1] ^= ROTATE(x[13] + x[ 9], 13);
        x[ 5] ^= ROTATE(x[ 1] + x[13], 18);
        x[14] ^= ROTATE(x[10] + x[ 6],  7);
        x[ 2] ^= ROTATE(x[14] + x[10],  9);
        x[ 6] ^= ROTATE(x[ 2] + x[14], 13);
        x[10] ^= ROTATE(x[ 6] + x[ 2], 18);
        x[ 3] ^= ROTATE(x[15] + x[11],  7);
        x[ 7] ^= ROTATE(x[ 3] + x[15],  9);
        x[11] ^= ROTATE(x[ 7] + x[ 3], 13);
        x[15] ^= ROTATE(x[11] + x[ 7], 18);
        x[ 1] ^= ROTATE(x[ 0] + x[ 3],  7);
        x[ 2] ^= ROTATE(x[ 1] + x[ 0],  9);
        x[ 3] ^= ROTATE(x[ 2] + x[ 1], 13);
        x[ 0] ^= ROTATE(x[ 3] + x[ 2], 18);
        x[ 6] ^= ROTATE(x[ 5] + x[ 4],  7);
        x[ 7] ^= ROTATE(x[ 6] + x[ 5],  9);
        x[ 4] ^= ROTATE(x[ 7] + x[ 6], 13);
        x[ 5] ^= ROTATE(x[ 4] + x[ 7], 18);
        x[11] ^= ROTATE(x[10] + x[ 9],  7);
        x[ 8] ^= ROTATE(x[11] + x[10],  9);
        x[ 9] ^= ROTATE(x[ 8] + x[11], 13);
        x[10] ^= ROTATE(x[ 9] + x[ 8], 18);
        x[12] ^= ROTATE(x[15] + x[14],  7);
        x[13] ^= ROTATE(x[12] + x[15],  9);
        x[14] ^= ROTATE(x[13] + x[12], 13);
        x[15] ^= ROTATE(x[14] + x[13], 18);
    }

    for (i=16; i--;) {
        x[i] += input[i];
    }

    SC_BIG_ENDIAN_32_COPY((UINT32*) output, 0, x, 16*sizeof(UINT32));
}

void salsa_keysetup(salsa_ctx_t *ctx, const UINT8 *k, UINT32 kbits)
{
  const UINT32 *constants;

  ctx->input[1] = U8TO32_LITTLE_ENDIAN(k + 0);
  ctx->input[2] = U8TO32_LITTLE_ENDIAN(k + 4);
  ctx->input[3] = U8TO32_LITTLE_ENDIAN(k + 8);
  ctx->input[4] = U8TO32_LITTLE_ENDIAN(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  ctx->input[11] = U8TO32_LITTLE_ENDIAN(k + 0);
  ctx->input[12] = U8TO32_LITTLE_ENDIAN(k + 4);
  ctx->input[13] = U8TO32_LITTLE_ENDIAN(k + 8);
  ctx->input[14] = U8TO32_LITTLE_ENDIAN(k + 12);
  ctx->input[0] = constants[0];
  ctx->input[5] = constants[1];
  ctx->input[10] = constants[2];
  ctx->input[15] = constants[3];
}

void salsa_ivsetup(salsa_ctx_t *ctx, const UINT8 *iv, const UINT8* counter)
{
  ctx->input[12] = (NULL == counter)? 0 : U8TO32_LITTLE_ENDIAN(counter);
  ctx->input[13] = (NULL == counter)? 0 : U8TO32_LITTLE_ENDIAN(counter + 4);
  ctx->input[14] = U8TO32_LITTLE_ENDIAN(iv + 0);
  ctx->input[15] = U8TO32_LITTLE_ENDIAN(iv + 4);
}

void salsa_ietf_ivsetup(salsa_ctx_t *ctx, const UINT8 *iv, const UINT8* counter)
{
  ctx->input[12] = (NULL == counter)? 0 : U8TO32_LITTLE_ENDIAN(counter);
  ctx->input[13] = U8TO32_LITTLE_ENDIAN(iv + 0);
  ctx->input[14] = U8TO32_LITTLE_ENDIAN(iv + 4);
  ctx->input[15] = U8TO32_LITTLE_ENDIAN(iv + 8);
}

void salsa_encrypt_bytes(salsa_ctx_t *ctx, const UINT8 *m, UINT8 *c, size_t bytes)
{
  UINT8 *ctarget;
  UINT8 output[64];
  size_t i;

  if (!bytes) return;

  for (;;) {
    salsa20_core(ctx->input, output);
    ctx->input[8] = PLUSONE(ctx->input[8]);
    if (!ctx->input[8]) {
      ctx->input[9] = PLUSONE(ctx->input[9]);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }
    if (bytes <= 64) {
      for (i = 0;i < bytes;++i) c[i] = m[i] ^ output[i];
      return;
    }
    for (i = 0;i < 64;++i) c[i] = m[i] ^ output[i];
    bytes -= 64;
    c += 64;
    m += 64;  }
}

void salsa_decrypt_bytes(salsa_ctx_t *ctx, const UINT8 *c, UINT8 *m, size_t bytes)
{
  salsa_encrypt_bytes(ctx, c, m, bytes);
}

void salsa_keystream_bytes(salsa_ctx_t *ctx, UINT8 *stream, size_t bytes)
{
  size_t i;
  for (i = 0;i < bytes;++i) stream[i] = 0;
  salsa_encrypt_bytes(ctx, stream, stream, bytes);
}
