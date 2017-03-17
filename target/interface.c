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
 * @file interface.c
 * @brief Provides a generic interface to RSA implementations.
 * @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
 * @license This project is released under the MIT License.
 */

/***********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <openssl/conf.h>
#include "simplersa.h"

/***********************************************************************/

/**
 * RSA key pair.
 */
RSA *RSA_KEYPAIR = NULL;

/***********************************************************************/

/**
 * Initialize RSA engine.
 *
 * @param Path file path to read the key from
 *
 * @return 0=success, else=error
 */
int RSA_init(const char *Path)
{
  /* init */
  int err = -1;
  FILE *keyfile = NULL;

  /* init libcrypto */
  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();

  /* open key file */
  keyfile = fopen(Path, "r");
  if (keyfile == NULL)
  {
    printf("[ERROR] Could not open given key file!\n");
    goto cleanup;
  }

  /* read key pair */
  RSA_KEYPAIR = RSA_new();
  if (!RSA_KEYPAIR)
  {
    printf("[ERROR] Could not allocate new RSA key pair!\n");
    goto cleanup;
  }
  if (PEM_read_RSAPrivateKey(keyfile, &RSA_KEYPAIR, NULL, NULL) == NULL)
  {
    printf("[ERROR] Could not read RSA key!\n");
    goto cleanup;
  }

  /* success */
  err = 0;

  /* clean up */
cleanup:
  if (keyfile)
    fclose(keyfile);
  return (err);
}

/**
 * Retrieve the RSA message size in bytes.
 *
 * @param Size contains size in bytes after call
 *
 * @return 0=success, else=error
 */
int RSA_size_msg(int *Size)
{
  if (!RSA_KEYPAIR)
  {
    printf("[ERROR] Please initialize RSA engine first!\n");
    return (-1);
  }
  *Size = RSA_size(RSA_KEYPAIR);
  return (0);
}

/**
 * Retrieve the RSA private exponent size in bytes.
 *
 * @param Size contains size in bytes after call
 *
 * @return 0=success, else=error
 */
int RSA_size_prvexp(int *Size)
{
  return (RSA_size_msg(Size));
}

/**
 * Set a custom RSA private exponent.
 *
 * @param PrivateExp private exponent to set
 * @param Length private exponent buffer size
 *
 * @return 0=success, else=error
 */
int RSA_set_prvexp(const char *PrivateExp, int Length)
{
  /* sanity check */
  if (!RSA_KEYPAIR)
  {
    printf("[ERROR] Please initialize RSA engine first!\n");
    return (-1);
  }

  /* init */
  int err = -1;
  BIGNUM *new_d = NULL;

  /* prepare new exponent */
  new_d = BN_new();
  if (!new_d)
  {
    printf("[ERROR] Could not allocate new private exponent!\n");
    goto cleanup;
  }
  if (!BN_zero(new_d))
  {
    printf("[ERROR] Could not zero new private exponent!\n");
    goto cleanup;
  }

  /* replace private exponent */
  if(!BN_hex2bn(&new_d, PrivateExp))
  {
    printf("[ERROR] Could not replace private exponent!\n");
    goto cleanup;
  }
  BN_clear_free(RSA_KEYPAIR->d);
  RSA_KEYPAIR->d = new_d;

  /* success */
  err = 0;

  /* clean up */
cleanup:
  if (err && new_d)
    BN_clear_free(new_d);
  return (err);
}

/**
 * RSA decryption without input padding.
 *
 * @param MsgLen number of bytes in input and output buffer
 * @param Input input buffer
 * @param Output output buffer
 *
 * @return 0=success, else=error
 */
int RSA_decrypt(int MsgLen, const unsigned char *Input,
                unsigned char* Output)
{
  /* sanity check */
  if (!RSA_KEYPAIR)
  {
    printf("[ERROR] Please initialize RSA engine first!\n");
    return (-1);
  }

  /* RSA decrypt */
  if (RSA_decrypt_simple(MsgLen, Input, Output, RSA_KEYPAIR))
  {
    printf("[ERROR] Could not perform RSA decrypt!\n");
    return (-1);
  }

  /* success */
  return (0);
}

/**
 * De-initialize RSA engine.
 *
 * @return 0=success, else=error
 */
int RSA_deinit()
{
  /* internals */
  if (RSA_KEYPAIR)
  {
    RSA_free(RSA_KEYPAIR);
    RSA_KEYPAIR = NULL;
  }

  /* libcrypto */
  FIPS_mode_set(0); 
  ENGINE_cleanup();
  CONF_modules_unload(1);
  EVP_cleanup();
  CRYPTO_cleanup_all_ex_data();
  ERR_remove_state(0); 
  ERR_free_strings();

  /* success */
  return (0);
}

