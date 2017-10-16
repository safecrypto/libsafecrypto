/*
chacha-merged.c version 20080118
D. J. Bernstein
Public domain.
*/

#include "chacha20.h"

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

void chacha_keysetup(chacha_ctx_t *ctx, const UINT8 *k, UINT32 kbits)
{
  const UINT32 *constants;

  ctx->input[4] = U8TO32_LITTLE_ENDIAN(k + 0);
  ctx->input[5] = U8TO32_LITTLE_ENDIAN(k + 4);
  ctx->input[6] = U8TO32_LITTLE_ENDIAN(k + 8);
  ctx->input[7] = U8TO32_LITTLE_ENDIAN(k + 12);
  if (kbits == 256) { /* recommended */
    k += 16;
    constants = sigma;
  } else { /* kbits == 128 */
    constants = tau;
  }
  ctx->input[0] = constants[0];
  ctx->input[1] = constants[1];
  ctx->input[2] = constants[2];
  ctx->input[3] = constants[3];
  ctx->input[8] = U8TO32_LITTLE_ENDIAN(k + 0);
  ctx->input[9] = U8TO32_LITTLE_ENDIAN(k + 4);
  ctx->input[10] = U8TO32_LITTLE_ENDIAN(k + 8);
  ctx->input[11] = U8TO32_LITTLE_ENDIAN(k + 12);
}

void chacha_ivsetup(chacha_ctx_t *ctx, const UINT8 *iv, const UINT8* counter)
{
  ctx->input[12] = (NULL == counter)? 0 : U8TO32_LITTLE_ENDIAN(counter);
  ctx->input[13] = (NULL == counter)? 0 : U8TO32_LITTLE_ENDIAN(counter + 4);
  ctx->input[14] = U8TO32_LITTLE_ENDIAN(iv + 0);
  ctx->input[15] = U8TO32_LITTLE_ENDIAN(iv + 4);
}

void chacha_ietf_ivsetup(chacha_ctx_t *ctx, const UINT8 *iv, const UINT8* counter)
{
  ctx->input[12] = (NULL == counter)? 0 : U8TO32_LITTLE_ENDIAN(counter);
  ctx->input[13] = U8TO32_LITTLE_ENDIAN(iv + 0);
  ctx->input[14] = U8TO32_LITTLE_ENDIAN(iv + 4);
  ctx->input[15] = U8TO32_LITTLE_ENDIAN(iv + 8);
}

void chacha_encrypt_bytes(chacha_ctx_t *ctx, const UINT8 *m, UINT8 *c, size_t bytes)
{
  UINT32 x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;
  UINT32 j0, j1, j2, j3, j4, j5, j6, j7, j8, j9, j10, j11, j12, j13, j14, j15;
  UINT8 *ctarget;
  UINT8 tmp[64];
  size_t i;

  if (!bytes) return;

  j0 = ctx->input[0];
  j1 = ctx->input[1];
  j2 = ctx->input[2];
  j3 = ctx->input[3];
  j4 = ctx->input[4];
  j5 = ctx->input[5];
  j6 = ctx->input[6];
  j7 = ctx->input[7];
  j8 = ctx->input[8];
  j9 = ctx->input[9];
  j10 = ctx->input[10];
  j11 = ctx->input[11];
  j12 = ctx->input[12];
  j13 = ctx->input[13];
  j14 = ctx->input[14];
  j15 = ctx->input[15];

  for (;;) {
    if (bytes < 64) {
      for (i = 0;i < bytes;++i) tmp[i] = m[i];
      m = tmp;
      ctarget = c;
      c = tmp;
    }
    x0 = j0;
    x1 = j1;
    x2 = j2;
    x3 = j3;
    x4 = j4;
    x5 = j5;
    x6 = j6;
    x7 = j7;
    x8 = j8;
    x9 = j9;
    x10 = j10;
    x11 = j11;
    x12 = j12;
    x13 = j13;
    x14 = j14;
    x15 = j15;
    for (i = 20;i > 0;i -= 2) {   /// @todo Should this be 20?
      QUARTERROUND(x0, x4, x8,x12)
      QUARTERROUND(x1, x5, x9,x13)
      QUARTERROUND(x2, x6,x10,x14)
      QUARTERROUND(x3, x7,x11,x15)
      QUARTERROUND(x0, x5,x10,x15)
      QUARTERROUND(x1, x6,x11,x12)
      QUARTERROUND(x2, x7, x8,x13)
      QUARTERROUND(x3, x4, x9,x14)
    }
    x0 = PLUS(x0,j0);
    x1 = PLUS(x1,j1);
    x2 = PLUS(x2,j2);
    x3 = PLUS(x3,j3);
    x4 = PLUS(x4,j4);
    x5 = PLUS(x5,j5);
    x6 = PLUS(x6,j6);
    x7 = PLUS(x7,j7);
    x8 = PLUS(x8,j8);
    x9 = PLUS(x9,j9);
    x10 = PLUS(x10,j10);
    x11 = PLUS(x11,j11);
    x12 = PLUS(x12,j12);
    x13 = PLUS(x13,j13);
    x14 = PLUS(x14,j14);
    x15 = PLUS(x15,j15);

    x0 = XOR(x0,U8TO32_LITTLE_ENDIAN(m + 0));
    x1 = XOR(x1,U8TO32_LITTLE_ENDIAN(m + 4));
    x2 = XOR(x2,U8TO32_LITTLE_ENDIAN(m + 8));
    x3 = XOR(x3,U8TO32_LITTLE_ENDIAN(m + 12));
    x4 = XOR(x4,U8TO32_LITTLE_ENDIAN(m + 16));
    x5 = XOR(x5,U8TO32_LITTLE_ENDIAN(m + 20));
    x6 = XOR(x6,U8TO32_LITTLE_ENDIAN(m + 24));
    x7 = XOR(x7,U8TO32_LITTLE_ENDIAN(m + 28));
    x8 = XOR(x8,U8TO32_LITTLE_ENDIAN(m + 32));
    x9 = XOR(x9,U8TO32_LITTLE_ENDIAN(m + 36));
    x10 = XOR(x10,U8TO32_LITTLE_ENDIAN(m + 40));
    x11 = XOR(x11,U8TO32_LITTLE_ENDIAN(m + 44));
    x12 = XOR(x12,U8TO32_LITTLE_ENDIAN(m + 48));
    x13 = XOR(x13,U8TO32_LITTLE_ENDIAN(m + 52));
    x14 = XOR(x14,U8TO32_LITTLE_ENDIAN(m + 56));
    x15 = XOR(x15,U8TO32_LITTLE_ENDIAN(m + 60));

    j12 = PLUSONE(j12);
    if (!j12) {
      j13 = PLUSONE(j13);
      /* stopping at 2^70 bytes per nonce is user's responsibility */
    }

    U32TO8_LITTLE_ENDIAN(c + 0,x0);
    U32TO8_LITTLE_ENDIAN(c + 4,x1);
    U32TO8_LITTLE_ENDIAN(c + 8,x2);
    U32TO8_LITTLE_ENDIAN(c + 12,x3);
    U32TO8_LITTLE_ENDIAN(c + 16,x4);
    U32TO8_LITTLE_ENDIAN(c + 20,x5);
    U32TO8_LITTLE_ENDIAN(c + 24,x6);
    U32TO8_LITTLE_ENDIAN(c + 28,x7);
    U32TO8_LITTLE_ENDIAN(c + 32,x8);
    U32TO8_LITTLE_ENDIAN(c + 36,x9);
    U32TO8_LITTLE_ENDIAN(c + 40,x10);
    U32TO8_LITTLE_ENDIAN(c + 44,x11);
    U32TO8_LITTLE_ENDIAN(c + 48,x12);
    U32TO8_LITTLE_ENDIAN(c + 52,x13);
    U32TO8_LITTLE_ENDIAN(c + 56,x14);
    U32TO8_LITTLE_ENDIAN(c + 60,x15);

    if (bytes <= 64) {
      if (bytes < 64) {
        for (i = 0;i < bytes;++i) ctarget[i] = c[i];
      }
      ctx->input[12] = j12;
      ctx->input[13] = j13;
      return;
    }
    bytes -= 64;
    c += 64;
    m += 64;
  }
}

void chacha_decrypt_bytes(chacha_ctx_t *ctx, const UINT8 *c, UINT8 *m, size_t bytes)
{
  chacha_encrypt_bytes(ctx, c, m, bytes);
}

void chacha_keystream_bytes(chacha_ctx_t *ctx, UINT8 *stream, size_t bytes)
{
  size_t i;
  for (i = 0;i < bytes;++i) stream[i] = 0;
  chacha_encrypt_bytes(ctx, stream, stream, bytes);
}
