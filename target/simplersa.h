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
 * @file simplersa.h
 * @brief Simple square-and-multiply RSA implementation.
 * @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
 * @license This project is released under the MIT License.
 */

/***********************************************************************/

#ifndef HEADER_SIMPLERSA_H
#define HEADER_SIMPLERSA_H

#include <openssl/bn.h>
#include <openssl/rsa.h>

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
                       unsigned char *Output, RSA *Key);

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
                       const BIGNUM *m, BN_CTX *ctx);

#endif /* HEADER_SIMPLERSA_H */

