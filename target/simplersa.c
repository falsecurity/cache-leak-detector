/************************************************************************
 * Copyright (c) 2016-2017 Andreas Zankl
 * 
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 * 
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 ***********************************************************************/

/**
 * @file simplersa.c
 * @brief Simple square-and-multiply RSA implementation.
 * @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
 * @license This project is released under the MIT License.
 */

/***********************************************************************/

#include <stdio.h>
#include "simplersa.h"

/**
 * RSA decryption without input padding.
 *
 * @param MsgLen number of bytes in input and output buffer
 * @param Input input buffer
 * @param Output output buffer
 * @param Key RSA key
 *
 * @return 0=success, else=error
 */
int RSA_decrypt_simple(int MsgLen, const unsigned char *Input,
                       unsigned char *Output, RSA *Key)
{
  /* init */
  int err = -1;
  BN_CTX *ctx = NULL;
  BIGNUM *f,*mod,*ret;
  int j,num;
  unsigned char *buf = NULL;

  /* prepare context */
  ctx = BN_CTX_new();
  if (ctx == NULL)
  {
    printf("[ERROR] Could not create new context!\n");
    goto cleanup;
  }
  BN_CTX_start(ctx);
  f = BN_CTX_get(ctx);
  mod = BN_CTX_get(ctx);
  ret = BN_CTX_get(ctx);
  num = BN_num_bytes(Key->n);
  buf = OPENSSL_malloc(num);
  if (!f || !mod || !ret || !buf)
  {
    printf("[ERROR] Could not prepare new context!\n");
    goto cleanup;
  }

  /* convert input */
  if (BN_bin2bn(Input, MsgLen, f) == NULL)
  {
    printf("[ERROR] Could not convert input to bignum!\n");
    goto cleanup;
  }
  if (BN_ucmp(f, Key->n) >= 0)
  {
    printf("[ERROR] Input too big for modulus!\n");
    goto cleanup;
  }

  /* exponentiate and reduce */
  if (RSA_mod_exp_simple(ret, f, Key->d, Key->n, ctx))
  {
    printf("[ERROR] Could not do modular exponentiation!\n");
    goto cleanup;
  }

  /* no padding */
  j=BN_bn2bin(ret, buf);
  if (RSA_padding_check_none(Output, num, buf, j, num) <= 0)
  {
    printf("[ERROR] Could not process padding!\n");
    goto cleanup;
  }

  /* success */
  err = 0;

  /* clean up */
cleanup:
  if (ctx)
  {
    BN_CTX_end(ctx);
    BN_CTX_free(ctx);
  }
  if (buf)
  {
    OPENSSL_cleanse(buf, num);
    OPENSSL_free(buf);
  }
  return (err);
}

/***********************************************************************/

/**
 * Simple square-and-multiply modular exponentiation. Implementation
 * based on the algorithm described in chapter 11.3 of "Schneier, B.:
 * Applied Cryptography (2nd Ed.): Protocols, Algorithms, and Source
 * Code in C. Wiley, New York (1995".
 *
 * @param r result
 * @param a base
 * @param p exponent
 * @param m modulus
 * @param ctx RSA context
 *
 * @return 0=success, else=error
 */
int RSA_mod_exp_simple(BIGNUM *r, const BIGNUM *a, const BIGNUM *p,
                       const BIGNUM *m, BN_CTX *ctx)
{
  /* init */
  int err = -1;
  BIGNUM *res, *base;
  int bits, i;
  BN_RECP_CTX *recp = NULL;

  /* prepare context */
  BN_CTX_start(ctx);
  res = BN_CTX_get(ctx);
  base = BN_CTX_get(ctx);
  if (!res || !base)
  {
    printf("[ERROR] Could not prepare new context (modexp)!\n");
    goto cleanup;
  }

  /* prepare temp variables */
  if (BN_copy(base, a) == NULL)
  {
    printf("[ERROR] Could not copy base!\n");
    goto cleanup;
  }
  if (!BN_one(res))
  {
    printf("[ERROR] Could not init result to one!\n");
    goto cleanup;
  }
  if (!BN_mod(base, base, m, ctx))
  {
    printf("[ERROR] Could not reduce base with modulus!\n");
    goto cleanup;
  }

  /* prepare multiplication */
  recp = BN_RECP_CTX_new();
  if (!recp)
  {
    printf("[ERROR] Could not create context for recip. mul.!\n");
    goto cleanup;
  }
  BN_RECP_CTX_init(recp);
  if (!BN_RECP_CTX_set(recp, m, ctx))
  {
    printf("[ERROR] Could not set modulus for recip. mul.!\n");
    goto cleanup;
  }

  /* exponentiate */
  bits = BN_num_bits(p);
  for (i = 0; i < bits; i++)
  {
    /* multiply */
    if (BN_is_bit_set(p, i))
    {
      if (!BN_mod_mul_reciprocal(res, res, base, recp, ctx))
      {
        printf("[ERROR] Could not multiply!\n");
        goto cleanup;
      }
    }

    /* square */
    if (!BN_mod_sqr(base, base, m, ctx))
    {
      printf("[ERROR] Could not square!\n");
      goto cleanup;
    }
  }

  /* copy result */
  if (BN_copy(r, res) == NULL)
  {
    printf("[ERROR] Could not copy result!\n");
    goto cleanup;
  }

  /* success */
  err = 0;

  /* clean up */
cleanup:
  if (ctx)
    BN_CTX_end(ctx);
  if (recp)
  {
    BN_RECP_CTX_free(recp);
    OPENSSL_free(recp);
  }
  if (!err)
    bn_check_top(r);
  return (err);
}

