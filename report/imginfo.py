##
# @package report.imginfo
# @file imginfo.py
# @brief Retrieve information about a given image.
# @author Andreas Zankl <andreas.zankl@aisec.fraunhofer.de>
# @license This project is released under the MIT License.

"""
Copyright (c) 2016-2017 Andreas Zankl

Permission is hereby granted, free of charge, to any person obtaining
a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including
without limitation the rights to use, copy, modify, merge, publish,
distribute, sublicense, and/or sell copies of the Software, and to
permit persons to whom the Software is furnished to do so, subject to
the following conditions:

The above copyright notice and this permission notice shall be
included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

======================================================================

The code below uses pyelftools to parse binary files. It can be
retrieved from https://github.com/eliben/pyelftools. Capstone is
used to disassemble binaries. It can be retrieved from
https://github.com/aquynh/capstone.
"""

import sys
import os
import re
import numpy
import capstone
from elftools.elf.elffile import ELFFile

"""
*************************************************************************
"""

##
# Hold information about an image section.
#
class SectionInfo(object):

    ##
    # Initialize internals.
    #
    def __init__(self):
        
        # internals
        self._Name = ''
        self._Addr = 0
        self._Size = 0
        self._Obj = None

"""
*************************************************************************
"""

##
# Hold information about an image symbol.
#
class SymbolInfo(object):

    ##
    # Initialize internals.
    #
    def __init__(self):
        
        # internals
        self._Name = ''
        self._Addr = 0
        self._Size = 0
        self._Type = ''
        self._Obj = None

"""
*************************************************************************
"""
##
# Retrieve information about a given image.
#
class ImageInfo(object):

    ##
    # Initialize internals.
    #
    #   @param ImagePath file path to image
    #
    def __init__(self, ImagePath):
        
        # internals
        self._Path = ImagePath
        self._Handle = None
        self._SizeBytes = 0
        self._Elf = None
        self._IsExecutable = False
        self._Sections = {}
        self._SectionsFast = None
        self._Segments = []
        self._Strings = {}
        self._Symbols = {}
        self._TextInstructions = {}
        self._PLTInstructions = {}
        self._SymbolsFast = None
        self._TextSection = None
        self._PLTSection = None
        self._SymbolTable = None
        self._StringTable = None

    ##
    # Get infos about the given image.
    #
    #   @return none
    #
    def parseImage(self):
        
        # basic stats
        self._SizeBytes = os.path.getsize(self._Path)
        
        # open
        self._Handle = open(self._Path, 'rb')
        self._Elf = ELFFile(self._Handle)
        
        # executable
        if self._Elf['e_type'] == 'ET_EXEC':
            self._IsExecutable = True

        # header string table
        hdstrtbl = None
        cnt = 0
        for sec in self._Elf.iter_sections():
            if (sec['sh_type'] == 'SHT_STRTAB') and (self._Elf['e_shstrndx'] == cnt):
                hdstrtbl = sec
                break
            cnt += 1
        if hdstrtbl is None:
            raise Exception("[ERROR] Could not find header string table!")
        
        # register segments
        for seg in self._Elf.iter_segments():
            self._Segments.append(seg)
        
        # register sections
        for sec in self._Elf.iter_sections():
            curname = hdstrtbl.get_string(sec['sh_name'])
            if (sec['sh_addr'] != 0):
                cursec = SectionInfo()
                cursec._Name = curname
                cursec._Addr = sec['sh_addr']
                cursec._Size = sec['sh_size']
                cursec._Obj = sec
                self._Sections[cursec._Addr] = cursec

        # special sections
        secnames = []
        for sec in self._Elf.iter_sections():
            if sec['sh_size'] > 0:
                secnames.append(hdstrtbl.get_string(sec['sh_name']))
        if ('.text' not in secnames):
            raise Exception("[ERROR] No text section found!")
        if (('.symtab' not in secnames) and ('.dynsym' not in secnames)):
            raise Exception("[ERROR] No symbol table found!")
        if (('.strtab' not in secnames) and ('.dynstr' not in secnames)):
            raise Exception("[ERROR] No string table found!")
        usedebugtables = (('.symtab' in secnames) and ('.strtab' in secnames))
        
        # register special sections
        for sec in self._Elf.iter_sections():
            if sec['sh_size'] > 0:
                cursec = SectionInfo()
                cursec._Name = hdstrtbl.get_string(sec['sh_name'])
                cursec._Addr = sec['sh_addr']
                cursec._Size = sec['sh_size']
                cursec._Obj = sec
                if cursec._Name == '.text':
                    self._TextSection = cursec
                elif cursec._Name == '.plt':
                    self._PLTSection = cursec
                elif (cursec._Name == '.symtab') and usedebugtables:
                    self._SymbolTable = cursec
                elif (cursec._Name == '.strtab') and usedebugtables:
                    self._StringTable = cursec
                elif (cursec._Name == '.dynsym') and not usedebugtables:
                    self._SymbolTable = cursec
                elif (cursec._Name == '.dynstr') and not usedebugtables:
                    self._StringTable = cursec

        # sanity check
        if (self._TextSection is None):
            raise Exception("[ERROR] Could not assign text section!")
        if (self._PLTSection is None):
            raise Exception("[ERROR] Could not assign plt section!")
        if (self._SymbolTable is None):
            raise Exception("[ERROR] Could not assign symbol table!")
        if (self._StringTable is None):
            raise Exception("[ERROR] Could not assign string table!")
        
        # parse strings
        binstr = self._StringTable._Obj.data()
        binstrdec = binstr.decode()
        curstart = 0
        for cmatch in re.finditer('\x00', binstrdec):
            curstr = binstr[curstart:cmatch.start()].decode("utf-8")
            if curstr != "":
                self._Strings[curstart] = curstr
            curstart = cmatch.start() + 1
        self._Strings[0] = ''
        
        # register symbols
        for symb in self._SymbolTable._Obj.iter_symbols():
            if (symb['st_value'] != 0) and \
               (symb['st_info']['type'] != 'STT_SECTION') and \
               (symb['st_info']['type'] != 'STT_FILE') and \
               (symb['st_info']['type'] != 'STT_NOTYPE') and \
               (symb['st_info']['bind'] != 'STB_LOCAL'):
                
                # new symbol
                cursymb = SymbolInfo()
                cursymb._Name = symb.name
                cursymb._Addr = symb['st_value']
                cursymb._Size = symb['st_size']
                cursymb._Type = symb['st_info']['type']
                cursymb._Obj = symb
                
                # fix name
                if cursymb._Name == '':
                    cursymb._Name = '0x%08x' % cursymb._Addr
                
                # safe add
                if cursymb._Addr in self._Symbols.keys():
                    if sys.stdout.isatty():
                        print ("[INFO] Symbols with same start addr: new=%s and old=%s" \
                               % (cursymb._Name, self._Symbols[cursymb._Addr]._Name))
                    if cursymb._Size == self._Symbols[cursymb._Addr]._Size:
                        self._Symbols[cursymb._Addr]._Name += ("+%s" % cursymb._Name)
                    elif cursymb._Size > self._Symbols[cursymb._Addr]._Size:
                        cursymb._Name += ("+%s(len=%d)" % \
                                          (self._Symbols[cursymb._Addr]._Name, \
                                           self._Symbols[cursymb._Addr]._Size))
                        self._Symbols[cursymb._Addr] = cursymb
                    elif cursymb._Size < self._Symbols[cursymb._Addr]._Size:
                        self._Symbols[cursymb._Addr]._Name += ("+%s(len=%d)" % \
                                                               (cursymb._Name, \
                                                                cursymb._Size))
                else:
                    self._Symbols[cursymb._Addr] = cursymb

        # prune overlay functions
        ksort = sorted(self._Symbols.keys())
        krem = []
        for i in range(0, len(ksort)-1):
            if ((self._Symbols[ksort[i]]._Addr + self._Symbols[ksort[i]]._Size) > \
                self._Symbols[ksort[i+1]]._Addr) and \
               ((self._Symbols[ksort[i]]._Addr + self._Symbols[ksort[i]]._Size) == \
                (self._Symbols[ksort[i+1]]._Addr + self._Symbols[ksort[i+1]]._Size)):
                krem.append((ksort[i], ksort[i+1]))
        for k in krem:
            if sys.stdout.isatty():
                print ("[INFO] Pruning overlay function %s." % self._Symbols[k[1]]._Name)
            self._Symbols[k[0]]._Name += ("+%s(%d)" % \
                                          (self._Symbols[k[1]]._Name, k[1]-k[0]))
            self._Symbols.pop(k[1])

        # fast access
        self._SectionsFast = numpy.zeros(len(self._Sections), \
                                         dtype=numpy.dtype([('Start', numpy.uintp, 1), \
                                                            ('Size', numpy.uintp, 1)]))
        ksort = sorted(self._Sections.keys())
        for i in range(0, len(self._Sections)):
            self._SectionsFast[i]['Start'] = self._Sections[ksort[i]]._Addr
            self._SectionsFast[i]['Size'] = self._Sections[ksort[i]]._Size
        self._SymbolsFast = numpy.zeros(len(self._Symbols), \
                                        dtype=numpy.dtype([('Start', numpy.uintp, 1), \
                                                           ('Size', numpy.uintp, 1)]))
        ksort = sorted(self._Symbols.keys())
        for i in range(0, len(self._Symbols)):
            self._SymbolsFast[i]['Start'] = self._Symbols[ksort[i]]._Addr
            self._SymbolsFast[i]['Size'] = self._Symbols[ksort[i]]._Size

        # consistency check
        for i in range(0, len(self._SectionsFast)-1):
            if self._SectionsFast[i]['Start'] + self._SectionsFast[i]['Size'] > \
               self._SectionsFast[i+1]['Start']:
                raise Exception('[ERROR] Inconsistent section placement!')
        for i in range(0, len(self._SymbolsFast)-1):
            if self._SymbolsFast[i]['Start'] + self._SymbolsFast[i]['Size'] > \
               self._SymbolsFast[i+1]['Start']:
                raise Exception('[ERROR] Inconsistent symbol placement: %s -> %s!' % \
                                (self._Symbols[self._SymbolsFast[i]['Start']]._Name, \
                                 self._Symbols[self._SymbolsFast[i+1]['Start']]._Name))
        
        # set up disassembler
        if 'x64' in self._Elf.get_machine_arch().lower():
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif 'x86' in self._Elf.get_machine_arch().lower():
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif 'arm' in self._Elf.get_machine_arch().lower():
            md = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif 'aarch64' in self._Elf.get_machine_arch().lower():
            md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM + \
                             capstone.CS_MODE_V8)
        else:
            raise Exception("[ERROR] Image architecture currently not supported!")
        md.skipdata = True
        
        # parse .text section
        instructions = md.disasm_lite(self._TextSection._Obj.data(), \
                                      self._TextSection._Addr)
        for (address, size, mnemonic, op_str) in instructions:
            self._TextInstructions[address] = (size, "%s\t%s" % (mnemonic, op_str))

        # parse .plt instructions
        instructions = md.disasm_lite(self._PLTSection._Obj.data(), \
                                      self._PLTSection._Addr)
        for (address, size, mnemonic, op_str) in instructions:
            self._PLTInstructions[address] = (size, "%s\t%s" % (mnemonic, op_str))

    ##
    # Get section from given address.
    #
    #   @param Address address within image
    #   @return the section of the address (None if error)
    #
    def getSection(self, Address):
        
        # find
        idx = numpy.argwhere(self._SectionsFast[:]['Start'] <= Address).flatten()
        if len(idx) == 0:
            return None
        
        # check
        if Address < self._SectionsFast[idx[-1]]['Start'] + \
           self._SectionsFast[idx[-1]]['Size']:
            return (self._Sections[self._SectionsFast[idx[-1]]['Start']])
        else:
            return None

    ##
    # Get symbol from given address.
    #
    #   @param Address address within image
    #   @return the symbol of the address (None if error)
    #
    def getSymbol(self, Address):
        
        # find
        idx = numpy.argwhere(self._SymbolsFast[:]['Start'] <= Address).flatten()
        if len(idx) == 0:
            return None
        
        # check
        if Address < self._SymbolsFast[idx[-1]]['Start'] + \
           self._SymbolsFast[idx[-1]]['Size']:
            return (self._Symbols[self._SymbolsFast[idx[-1]]['Start']])
        else:
            return None

    ##
    # Get instruction from given address.
    #
    #   @param Address address within image
    #   @return size of instr. and assembly code (None if error)
    #
    def getInstruction(self, Address):
        
        # get section
        sec = self.getSection(Address)
        if sec is None:
            return None
  
        # search
        if sec._Name == '.text':
            if Address in self._TextInstructions.keys():
                return (self._TextInstructions[Address])
        elif sec._Name == '.plt':
            if Address in self._PLTInstructions.keys():
                return (self._PLTInstructions[Address])
        
        # error
        return None

