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
 * @file target.c
 * @brief Target program executing RSA decryptions.
 * @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
 * @license This project is released under the MIT License.
 */

/***********************************************************************/

#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include <unistd.h>

/***********************************************************************/

/*
 * Functions.
 */
void printHelp();
unsigned long genSeed(unsigned long a, unsigned long b, unsigned long c);
void* rsaWorker(void *Params);

/*
 * RSA interface.
 */
extern int RSA_init(const char *Path);
extern int RSA_size_msg(int *Size);
extern int RSA_size_prvexp(int *Size);
extern int RSA_set_prvexp(const char *PrivateExp, int Length);
extern int RSA_decrypt(int MsgLen, const unsigned char *Input,
                       unsigned char* Output);
extern int RSA_deinit();

/**
 * Thread struct.
 */
typedef struct tparams {
  /**
   * Length of input and output.
   */
  int MsgLen;

  /**
   * Cipher input.
   */
  const unsigned char *Input;

  /**
   * Cipher output.
   */
  unsigned char* Output;
} tparams_t;

/***********************************************************************/

/**
 * Print the command help text.
 */
void printHelp()
{
  printf("Usage:\n\n");
  printf("target <KeyFile> <ExpFile>\n\n");
  printf("  <KeyFile> .... file path to a PEM encoded RSA key\n");
  printf("  <ExpFile> .... file path to save generated exponents to\n");
  printf("\n");
}

/**
 * Target program entry point.
 *
 * @param argc number of command line arguments
 * @param argv command line arguments
 *
 * @return 0=success, else=error
 */
int main(int argc, const char *argv[])
{
  /* sanity check */
  if (argc != 3)
  {
    printHelp();
    return (-1);
  }

  /* init */
  int err = -1;
  int i,msgsize,keysize;
  FILE *outfile = NULL;
  char *newexp = NULL;
  unsigned char *newexp_bin = NULL;
  unsigned char *inbuf = NULL;
  unsigned char *outbuf = NULL;
  pthread_t worker;
  pthread_attr_t *wattr = NULL;
  tparams_t *params = NULL;
  void *tret = (void*)-1;

  /* prepare RNG */
  srand(genSeed(clock(), time(NULL), getpid()));

  /* prepare RSA */
  if (RSA_init(argv[1]))
  {
    printf("[ERROR] RSA_init failed!\n");
    goto cleanup;
  }
  if (RSA_size_msg(&msgsize))
  {
    printf("[ERROR] RSA_size_msg failed!\n");
    goto cleanup;
  }
  if (RSA_size_prvexp(&keysize))
  {
    printf("[ERROR] RSA_size_prvexp failed!\n");
    goto cleanup;
  }

  /* generate random private exponent */
  newexp = (char*)malloc(keysize * 2 + 1);
  if (!newexp)
  {
    printf("[ERROR] Could not allocate new private exponent!\n");
    goto cleanup;
  }
  newexp_bin = (unsigned char*)malloc(keysize);
  if (!newexp_bin)
  {
    printf("[ERROR] Could not allocate new binary copy!\n");
    goto cleanup;
  }
  newexp_bin[0] = (unsigned char)((rand() % 256) & 0x7F);
  sprintf(newexp, "%02X", newexp_bin[0]);
  for (i = 1; i < keysize; i++)
  {
    newexp_bin[i] = (unsigned char)(rand() % 256);
    sprintf(newexp + i*2, "%02X", newexp_bin[i]);
  }
  newexp[keysize * 2] = '\0';

  /* set new private exponent */
  if (RSA_set_prvexp(newexp, keysize * 2))
  {
    printf("[ERROR] RSA_set_prvexp failed!\n");
    goto cleanup;
  }

  /* prepare IO buffers */
  inbuf = (unsigned char*)malloc(msgsize);
  if (!inbuf)
  {
    printf("[ERROR] Could not allocate input buffer!\n");
    goto cleanup;
  }
  outbuf = (unsigned char*)malloc(msgsize);
  if (!outbuf)
  {
    printf("[ERROR] Could not allocate output buffer!\n");
    goto cleanup;
  }
  for (i = 0; i < msgsize; i++)
  {
    inbuf[i] = (unsigned char)(rand() % 256);
    outbuf[i] = 0x00;
  }
  inbuf[0] = 0x00;

  /* prepare threading */
  wattr = (pthread_attr_t*)malloc(sizeof(pthread_attr_t));
  memset(wattr, 0, sizeof(pthread_attr_t));
  if (pthread_attr_init(wattr))
  {
    printf("[ERROR] PThread attribute init failed!\n");
    goto cleanup;
  }
  params = (tparams_t*)malloc(sizeof(tparams_t));
  if (!params)
  {
    printf("[ERROR] Could not allocate thread parameters!\n");
    goto cleanup;
  }
  params->MsgLen = msgsize;
  params->Input = inbuf;
  params->Output = outbuf;

  /* start decrypt thread */
  if (pthread_create(&worker, wattr, rsaWorker, (void*)params))
  {
    printf("[ERROR] PThread create failed!\n");
    goto cleanup;
  }
  if (pthread_join(worker, &tret))
  {
    printf("[ERROR] PThread join failed!\n");
    goto cleanup;
  }
  if (tret)
  {
    printf("[ERROR] RSA worker thread failed!\n");
    goto cleanup;
  }

  /* save exponent */
  outfile = fopen(argv[2], "ab");
  if (!outfile)
  {
    printf("[ERROR] Could not open ExpFile!\n");
    goto cleanup;
  }
  fwrite(newexp_bin, sizeof(unsigned char), keysize, outfile);

  /* success */
  err = 0;

  /* clean up */
cleanup:
  if (RSA_deinit())
    printf("[WARN] RSA_deinit failed!\n");
  if (outfile)
    fclose(outfile);
  if (newexp)
    free(newexp);
  if (newexp_bin)
    free(newexp_bin);
  if (inbuf)
    free(inbuf);
  if (outbuf)
    free(outbuf);
  if (params)
    free(params);
  if (wattr)
  {
    pthread_attr_destroy(wattr);
    free(wattr);
  }
  return (err);
}

/***********************************************************************/

/**
 * Simple integer hash to generate a random seed for srand(). Code taken
 * from http://burtleburtle.net/bob/hash/evahash.html.
 *
 * @param a Input 1
 * @param b Input 2
 * @param c Input 3
 *
 * @return hash
 */
unsigned long genSeed(unsigned long a, unsigned long b, unsigned long c)
{
  a=a-b;  a=a-c;  a=a^(c>>13);
  b=b-c;  b=b-a;  b=b^(a<< 8);
  c=c-a;  c=c-b;  c=c^(b>>13);
  a=a-b;  a=a-c;  a=a^(c>>12);
  b=b-c;  b=b-a;  b=b^(a<<16);
  c=c-a;  c=c-b;  c=c^(b>> 5);
  a=a-b;  a=a-c;  a=a^(c>> 3);
  b=b-c;  b=b-a;  b=b^(a<<10);
  c=c-a;  c=c-b;  c=c^(b>>15);
  return c;
}

/**
 * Perform RSA decryption in separate thread.
 *
 * @param Params decryption arguments
 *
 * @return 0=success, else=error
 */
void* rsaWorker(void *Params)
{
  long long err = RSA_decrypt(((tparams_t*)Params)->MsgLen,
                              ((tparams_t*)Params)->Input,
                              ((tparams_t*)Params)->Output);
  return((void*)err);
}

