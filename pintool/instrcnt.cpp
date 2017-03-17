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
 * @file instrcnt.cpp
 * @brief Instruction pointer tracing tool for Pin.
 * @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
 * @license This project is released under the MIT License.
 */

/***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <stdint.h>
#include <map>
#include "pin.H"

/***********************************************************************/

/**
 * Image info struct.
 */
struct IMAGEINFO {
  /**
   * Image ID.
   */
  uint32_t ID;

  /**
   * Image name.
   */
  char* Name;

  /**
   * Highest address.
   */
  uintptr_t AddressHigh;

  /**
   * Lowest address.
   */
  uintptr_t AddressLow;

  /**
   * Number of addresses.
   */
  uint32_t Size;

  /**
   * Link to previous image.
   */
  IMAGEINFO* Previous;
};

/***********************************************************************/

/*
 * Functions.
 */
void printHelp();
VOID imgLoad(IMG img, VOID *v);
VOID threadStart(THREADID tIdx, CONTEXT *ctxt, INT32 flags, VOID *v);
VOID threadEnd(THREADID tIdx, const CONTEXT *ctxt, INT32 code, VOID *v);
VOID traceInstr(INS ins, VOID *v);
VOID countInstr(VOID *v, THREADID id);
VOID finish(INT32 code, VOID *v);

/**
 * Handle of output file.
 */
FILE *OUTFILE = NULL;

/**
 * Instrumentation activate flag.
 */
unsigned int ACTIVE = 0;

/**
 * Pointer to last entry in image map.
 */
IMAGEINFO* LASTIMAGE = NULL;

/**
 * Map of (Image ID, Image Info).
 */
std::map<uint32_t, IMAGEINFO*> IMAGES;

/**
 * Image map iterator.
 */
typedef std::map<uint32_t, IMAGEINFO*>::iterator IMAGES_ITER;

/**
 * Map of (Image ID, Instruction Execution Counter).
 */
std::map<uint32_t, uint32_t*> INSTR;

/**
 * Instruction map iterator.
 */
typedef std::map<uint32_t, uint32_t*>::iterator INSTR_ITER;

/***********************************************************************/

/**
 * Command line argument -o ... output file path
 * @return Usage string.
 */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o",
                            "instrcnt.bin", "output file path");

/***********************************************************************/

/**
 * Print the command help text.
 */
void printHelp()
{
  printf("[INFO] This tool keeps track of the number of times each\n \
                 instruction is executed during a program run.\n\n");
  printf("%s\n", KNOB_BASE::StringKnobSummary().c_str());
}

/**
 * Pintool entry point.
 *
 * @param argc number of command line arguments
 * @param argv command line arguments
 *
 * @return 0=success, else=error
 */
int main(int argc, char *argv[])
{
  /* prepare Pin */
  if (PIN_Init(argc, argv))
  {
    printHelp();
    return (-1);
  }

  /* open output file */
  string outfilepath = KnobOutputFile.Value();
  if (outfilepath.empty())
  {
    printf("[ERROR] No output file specified!\n");
    return (-1);
  }
  OUTFILE = fopen(outfilepath.c_str(), "ab");
  if (OUTFILE == NULL)
  {
    printf("[ERROR] Could not open output file!\n");
    return (-1);
  }

  /* register callbacks */
  IMG_AddInstrumentFunction(imgLoad, 0);
  INS_AddInstrumentFunction(traceInstr, 0);
  PIN_AddThreadStartFunction(threadStart, 0);
  PIN_AddThreadFiniFunction(threadEnd, 0);
  PIN_AddFiniFunction(finish, 0);

  /* start Pin */
  PIN_StartProgram();

  /* success */
  return (0);
}

/***********************************************************************/

/**
 * Image load routine.
 *
 * @param img loaded image
 * @param v callback value
 *
 * @return none
 */
VOID imgLoad(IMG img, VOID *v)
{
  /* only valid images */
  if (!IMG_Valid(img))
    return;

  /* init */
  uint32_t id = IMG_Id(img);
  string name = IMG_Name(img);
  uintptr_t high = IMG_HighAddress(img);
  uintptr_t low = IMG_LowAddress(img);
  unsigned int size = high - low + 1;

  /* register */
  if (IMAGES.find(id) == IMAGES.end())
  {
    /* new image info */
    IMAGEINFO* ninfo = (IMAGEINFO*)malloc(sizeof(IMAGEINFO));
    if (ninfo == NULL)
      PIN_ExitApplication(-1);
    memset(ninfo, 0, sizeof(IMAGEINFO));

    /* allocate image name buffer */
    ninfo->Name = (char*)malloc(name.size()+1);
    if (ninfo->Name == NULL)
    {
      free(ninfo);
      PIN_ExitApplication(-1);
    }
    memcpy(ninfo->Name, name.c_str(), name.size());
    ninfo->Name[name.size()] = '\0';

    /* insert */
    ninfo->ID = id;
    ninfo->AddressHigh = high;
    ninfo->AddressLow = low;
    ninfo->Size = size;
    ninfo->Previous = NULL;
    IMAGES.insert(std::pair<uint32_t, IMAGEINFO*>(ninfo->ID, ninfo));

    /* update ring */
    IMAGEINFO* curptr = NULL;
    for(IMAGES_ITER itr = IMAGES.begin(); itr != IMAGES.end(); itr++)
    {
      /* skip first item */
      if (curptr == NULL)
      {
        curptr = itr->second;
        continue;
      }
      itr->second->Previous = curptr;
      curptr = itr->second;
    }
    LASTIMAGE = curptr;

    /* prepare instruction map */
    uint32_t* data = (uint32_t*)malloc(size * sizeof(uint32_t));
    if (data == NULL)
      PIN_ExitApplication(-1);
    memset(data, 0, size * sizeof(uint32_t));
    INSTR.insert(std::pair<uint32_t, uint32_t*>(ninfo->ID, data));
  }
}

/**
 * Thread start routine.
 *
 * @param tIdx thread ID
 * @param ctxt register state of the thread
 * @param flags OS falgs for the thread
 * @param v callback value
 *
 * @return none
 */
VOID threadStart(THREADID tIdx, CONTEXT *ctxt, INT32 flags, VOID *v)
{
  /* only activate, if not main thread */
  if (tIdx > 0)
    ACTIVE = 1;
}

/**
 * Thread end routine.
 *
 * @param tIdx thread ID
 * @param ctxt register state of the thread
 * @param code OS termination code of the thread
 * @param v callback value
 *
 * @return none
 */
VOID threadEnd(THREADID tIdx, const CONTEXT *ctxt, INT32 code, VOID *v)
{
  /* only deactivate, if not main thread */
  if (tIdx > 0)
    ACTIVE = 0;
}

/***********************************************************************/

/**
 * Instruction trace routine.
 *
 * @param ins instruction
 * @param v callback value
 *
 * @return none
 */
VOID traceInstr(INS ins, VOID *v)
{
  /* only valid instructions */
  if (INS_Valid(ins))
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)countInstr,
                   IARG_INST_PTR, IARG_THREAD_ID, IARG_END);
}

/**
 * Count the instruction execution.
 *
 * @param v instruction pointer
 * @param id thread id
 *
 * @return none
 */
VOID countInstr(VOID *v, THREADID id)
{
  /* only, if active */
  if (!ACTIVE)
    return;

  /* init */
  uintptr_t caddr = (uintptr_t)v;
  IMAGEINFO* cinfo = LASTIMAGE;

  /* find image */
  while (cinfo)
  {
    if (caddr >= cinfo->AddressLow && caddr <= cinfo->AddressHigh)
    {
      INSTR[cinfo->ID][caddr - cinfo->AddressLow] += 1;
      break;
    }
    cinfo = cinfo->Previous;
  }
}

/***********************************************************************/

/**
 * Finish tracing and clean up.
 *
 * @param code OS termination code
 * @param v callback value
 *
 * @return none
 */
VOID finish(INT32 code, VOID *v)
{
  /*
   * Store trace file
   * 
   * uint32_t   ImageNumber
   * 
   * for each image:
   *   uint32_t   NameLength
   *   uint32_t   SampleNumber (# of non-zero samples)
   *   uint64_t   HighAddress
   *   uint64_t   LowAddress
   *   char*      Name (not null-terminated)
   *   struct*    uint32_t Offset | uint32_t Count
   */
  uint32_t imgnum = IMAGES.size();
  fwrite(&imgnum, sizeof(uint32_t), 1, OUTFILE);
  for(IMAGES_ITER itr = IMAGES.begin(); itr != IMAGES.end(); itr++)
  {
    /* name length */
    uint32_t len = strlen(itr->second->Name);
    fwrite(&len, sizeof(uint32_t), 1, OUTFILE);

    /* sample number */
    uint32_t num = 0;
    for (uint32_t i = 0; i < itr->second->Size; i++)
      if (INSTR[itr->first][i] > 0)
        num++;
    fwrite(&num, sizeof(uint32_t), 1, OUTFILE);

    /* addresses */
    fwrite(&(itr->second->AddressHigh), sizeof(uint64_t), 1, OUTFILE);
    fwrite(&(itr->second->AddressLow), sizeof(uint64_t), 1, OUTFILE);

    /* name */
    fwrite(itr->second->Name, sizeof(char), len, OUTFILE);

    /* samples */
    for (uint32_t i = 0; i < itr->second->Size; i++)
    {
      if (INSTR[itr->first][i] > 0)
      {
        fwrite(&i, sizeof(uint32_t), 1, OUTFILE);
        fwrite(&(INSTR[itr->first][i]), sizeof(uint32_t), 1, OUTFILE);
      }
    }
  }

  /* clear maps */
  for(IMAGES_ITER itr = IMAGES.begin(); itr != IMAGES.end(); itr++)
  {
    free(itr->second->Name);
    free(itr->second);
  }
  for(INSTR_ITER itr = INSTR.begin(); itr != INSTR.end(); itr++)
  {
    free(itr->second);
  }

  /* close files */
  if (OUTFILE)
    fclose(OUTFILE);
}

