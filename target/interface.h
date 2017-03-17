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
 * @file interface.h
 * @brief Provides a generic interface to RSA implementations.
 * @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
 * @license This project is released under the MIT License.
 */

/***********************************************************************/

#ifndef HEADER_INTERFACE_H
#define HEADER_INTERFACE_H

/**
 * Initialize RSA engine.
 *
 * @param Path file path to read the key from
 *
 * @return 0=success, else=error
 */
int RSA_init(const char *Path);

/**
 * Retrieve the RSA message size in bytes.
 *
 * @param Size contains size in bytes after call
 *
 * @return 0=success, else=error
 */
int RSA_size_msg(int *Size);

/**
 * Retrieve the RSA private exponent size in bytes.
 *
 * @param Size contains size in bytes after call
 *
 * @return 0=success, else=error
 */
int RSA_size_prvexp(int *Size);

/**
 * Set a custom RSA private exponent.
 *
 * @param PrivateExp private exponent to set
 * @param Length private exponent buffer size
 *
 * @return 0=success, else=error
 */
int RSA_set_prvexp(const char *PrivateExp, int Length);

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
                unsigned char* Output);

/**
 * De-initialize RSA engine.
 *
 * @return 0=success, else=error
 */
int RSA_deinit();

#endif /* HEADER_INTERFACE_H */

