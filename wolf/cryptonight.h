#ifndef __CRYPTONIGHT_H
#define __CRYPTONIGHT_H

struct cryptonight_ctx;

typedef void (cryptonight_func)(void *output, const void *input, struct cryptonight_ctx *ctx);
cryptonight_func cryptonight_hash_dumb;
cryptonight_func cryptonight_hash_aesni;

struct cryptonight_ctx *cryptonight_ctx();


#endif
