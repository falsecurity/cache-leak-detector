##
# @package report.instrcnt
# @file instrcnt.py
# @brief Store measurements of the instrcnt Pintool.
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
"""

import struct
import numpy
import os

##
# Store measurements of the instrcnt Pintool.
#
class Measurements(object):
    
    ##
    # Maximum length of an image name.
    #
    MAX_IMG_NAME_LEN = 1024
    
    ##
    # Numpy dtype to store image infos.
    #
    IMG_DTYPE = numpy.dtype([('ID', numpy.int, 1), \
                             ('Name', numpy.str, MAX_IMG_NAME_LEN), \
                             ('HighAddr', numpy.uintp, 1), \
                             ('LowAddr', numpy.uintp, 1), \
                             ('Addresses', numpy.uintp, 1)])
    
    ##
    # Initialize internals.
    #
    def __init__(self):
        
        # internals
        self._ImgNum = 0
        self._MeasNum = 0
        self._KeySizeBits = 0
        self._KeySizeBytes = 0
        self._ImageData = {}
        self._KeyData = None
        self._ImageInfo = None

    ##
    # Parse measurements from given files.
    #
    #   @param KeySizeBytes key size in bytes
    #   @param InstrCntFile path to instr. count file
    #   @param ExpFile path to exponent file
    #   @return none
    #
    def parse(self, KeySizeBytes, InstrCntFile, ExpFile):  
             
        # init
        self._KeySizeBytes = int(KeySizeBytes)
        self._KeySizeBits = int(KeySizeBytes * 8)
        self._MeasNum = int(os.path.getsize(ExpFile) / KeySizeBytes)
        self._KeyData = numpy.zeros((self._MeasNum, self._KeySizeBytes), \
                                    dtype=numpy.uint8)

        # parse keys
        kfile = open(ExpFile, "rb")
        for i in range (0, self._MeasNum):
            buf = kfile.read(self._KeySizeBytes)
            self._KeyData[i] = numpy.array(list(buf), dtype=numpy.uint8)
        kfile.close()

        # parse measurements
        mfile = open(InstrCntFile, "rb")
        curmeas = 0
        imginit = 0
        uniqueoffsets = {}
        while True:
            # number of images
            buf = mfile.read(4)
            numimg = struct.unpack("@I", buf)[0]
            
            # image info store
            if self._ImgNum == 0:
                self._ImgNum = numimg
                self._ImageInfo = numpy.zeros(self._ImgNum, dtype=Measurements.IMG_DTYPE)

            # sanity check
            if numimg != self._ImgNum:
                mfile.close()
                raise Exception ("[ERROR] Number of images differ in measurements!")
            
            # process images
            for curimg in range(0, self._ImgNum):
                # rest of header
                buf = mfile.read(4)
                namelen = struct.unpack("@I", buf)[0]
                buf = mfile.read(4)
                samplenum = struct.unpack("@I", buf)[0]
                buf = mfile.read(8)
                highaddr = struct.unpack("@P", buf)[0]
                buf = mfile.read(8)
                lowaddr = struct.unpack("@P", buf)[0]
                buf = mfile.read(namelen)
                
                # check img name length
                if (namelen > Measurements.MAX_IMG_NAME_LEN):
                    mfile.close()
                    raise Exception ("[ERROR] Image name length exceeds maximum (%d)!" \
                                     % Measurements.MAX_IMG_NAME_LEN)
                
                # save image info
                if not imginit:
                    self._ImageInfo[curimg]['ID'] = curimg
                    self._ImageInfo[curimg]['Name'] = buf.decode("utf-8")
                    self._ImageInfo[curimg]['HighAddr'] = highaddr
                    self._ImageInfo[curimg]['LowAddr'] = lowaddr
                    self._ImageInfo[curimg]['Addresses'] = highaddr - lowaddr + 1
                    uniqueoffsets[curimg] = numpy.zeros(0, dtype=numpy.uint32)

                # sanity checks
                if (self._ImageInfo[curimg]['Name'] != buf.decode("utf-8")) or \
                   (self._ImageInfo[curimg]['Addresses'] != highaddr - lowaddr + 1):
                    mfile.close()
                    raise Exception ("[ERROR] Inconsistent image data detected!")

                # process samples
                buf = mfile.read(samplenum * 8)
                samples = numpy.array(struct.unpack(("@%dI" % (samplenum * 2)), buf), \
                                      dtype=numpy.uint32)
                indices = samples[0:len(samples):2]
                uniqueoffsets[curimg] = numpy.union1d(uniqueoffsets[curimg], indices)
            
            # store img info only once
            if not imginit:
                imginit = 1
            
            # progress
            curmeas += 1
            if curmeas == self._MeasNum:
                break
        
        # create image data
        for i in range(0, self._ImgNum):
            self._ImageData[i] = numpy.zeros(len(uniqueoffsets[i]), dtype=numpy.dtype( \
                                             [('Offset', numpy.uint32, 1), \
                                              ('Samples', numpy.uint32, self._MeasNum)]))
            self._ImageData[i]['Offset'] = uniqueoffsets[i]
        
        # process measurements
        mfile.seek(0)
        curmeas = 0
        while True:
            # number of images
            buf = mfile.read(4)

            # process images
            for curimg in range(0, self._ImgNum):
                # rest of header
                buf = mfile.read(4)
                namelen = struct.unpack("@I", buf)[0]
                buf = mfile.read(4)
                samplenum = struct.unpack("@I", buf)[0]
                buf = mfile.read(16 + namelen)

                # process samples
                buf = mfile.read(samplenum * 8)
                samples = numpy.array(struct.unpack(("@%dI" % (samplenum * 2)), buf), \
                                      dtype=numpy.uint32)
                indices = samples[0:len(samples):2]
                indices = numpy.searchsorted(self._ImageData[curimg]['Offset'], indices)
                values = samples[1:len(samples):2]
                self._ImageData[curimg]['Samples'][:,curmeas][indices] = values
                
            # progress
            curmeas += 1
            if curmeas == self._MeasNum:
                break

        # close files
        mfile.close()

    ##
    # Load internals from a Numpy file.
    #
    #   @param NumpyFile path to Numpy file
    #   @return none
    #
    def load(self, NumpyFile):    
           
        # open file
        nfile = numpy.load(NumpyFile)
        
        # load internals
        self._ImgNum = nfile['_ImgNum'][0]
        self._MeasNum = nfile['_MeasNum'][0]
        self._KeySizeBits = nfile['_KeySizeBits'][0]
        self._KeySizeBytes = nfile['_KeySizeBytes'][0]
        self._KeyData = nfile['_KeyData']
        self._ImageInfo = nfile['_ImageInfo']
        for idx in range(0, self._ImgNum):
            self._ImageData[idx] = nfile[('arr_%d' % idx)]
        
        # close file
        nfile.close()
        
    ##
    # Save internals to a Numpy file.
    #
    #   @param NumpyFile path to Numpy file
    #   @return none
    #  
    def save(self, NumpyFile):
        
        # open file
        nfile = open(NumpyFile, "wb")

        # save internals
        numpy.savez_compressed(nfile,
                    _ImgNum = numpy.array([self._ImgNum]),
                    _MeasNum = numpy.array([self._MeasNum]),
                    _KeySizeBits = numpy.array([self._KeySizeBits]),
                    _KeySizeBytes = numpy.array([self._KeySizeBytes]),
                    _KeyData = self._KeyData,
                    _ImageInfo = self._ImageInfo,
                    *[self._ImageData[idx] for idx in range(0, self._ImgNum)])
        
        # close file
        nfile.close()

