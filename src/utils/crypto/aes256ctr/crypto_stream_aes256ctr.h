#ifndef CRYPTO_STREAM_AES256CTR_H
#define CRYPTO_STREAM_AES256CTR_H

#ifdef ENABLE_AES_CTR_STREAM
int crypto_stream_aes256ctr(unsigned char *c,unsigned long long clen, const unsigned char *n, const unsigned char *k);
#endif

#endif

