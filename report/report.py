#!/usr/bin/python3

##
# @package report.report
# @file report.py
# @brief Report information about leaking instructions.
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

"""
*************************************************************************
"""

import os
import sys
import docopt
import math
import numpy
import scipy.stats
from instrcnt import Measurements
from imginfo import ImageInfo

"""
*************************************************************************
"""

##
# Calculate the Pearson correlation coefficient
# and catch special cases. If the correlation
# fails, 0 is returned.
#
#   @param A first sequence
#   @param B second sequence
#   @return Pearson correlation coefficient
#
numpy.seterr(all='raise')
def pearson(A, B):
    
    # Pearson
    coeff = 0.0
    try:
        coeff = scipy.stats.pearsonr(A, B)[0]
        if math.isnan(coeff):
            coeff = 0.0
    except:
        coeff = 0.0
    return (coeff)

##
# Calculate the hamming weight of all values
# within the given array.
#
#   @param A 1-D byte array
#   @return Hamming weight
#
def hweight(A):
    
    # hamming weight
    return (numpy.count_nonzero(numpy.unpackbits(A.flatten())))

"""
*************************************************************************
"""

##
# Program help text.
#
DOC = """
usage:
   report [NUMPY_FILE]
"""

"""
*************************************************************************
"""

# @cond IGNORE
# get cmd line arguments
cmdargs = docopt.docopt(DOC, version='report 0.1')
if (None in cmdargs.values()):
    print (DOC)
    sys.exit()

# arguments
nfile = os.path.expanduser(os.path.expandvars(cmdargs['NUMPY_FILE']))

# load measurements
meas = Measurements()
meas.load(nfile)

# hamming weights of exponents
hwexp = numpy.array(numpy.apply_along_axis(hweight, 1, meas._KeyData), \
                    dtype=numpy.uint)

# significance threshold
df = meas._MeasNum-2
tconf = scipy.stats.t.ppf(0.999999, df)
sigthres  = numpy.sqrt(numpy.power(tconf, 2) / (numpy.power(tconf, 2) + df))
print ("Significance Threshold: %.4f" % sigthres)
print ("")

# iterate over measurements
for i in range(0, meas._ImgNum):
    # info
    print ("*************************************")
    print ("Image: %s" % meas._ImageInfo[i]['Name'])
    
    # skip if not found
    if (not os.path.exists(meas._ImageInfo[i]['Name'])) or \
       (not os.path.isfile(meas._ImageInfo[i]['Name'])):
        print ("File not found!")
        print ("")
        print ("")
        continue
    
    # skip if no active instructions
    if (len(meas._ImageData[i]) == 0):
        print ("No active instructions!")
        print ("")
        print ("")
        continue
    
    # get image
    imginfo = ImageInfo(meas._ImageInfo[i]['Name'])
    imginfo.parseImage()
    
    # correlate
    outputstring = {}
    offsetsize = {}
    numleaks = 0
    for j in range(0, len(meas._ImageData[i])):
        # skip if not data
        if len(meas._ImageData[i][j]['Samples']) == 0:
            continue
        
        # correlate
        curcoeff = pearson(meas._ImageData[i][j]['Samples'], hwexp)
        
        # document leak
        if abs(curcoeff) >= sigthres:
            # get location
            curoffset = meas._ImageData[i][j]['Offset']
            if imginfo._IsExecutable:
                curaddr = curoffset + meas._ImageInfo[i]['LowAddr']
            else:
                curaddr = curoffset
            
            # assign section
            cursec = imginfo.getSection(curaddr)
            cursecname = "unknown" if cursec is None else cursec._Name
            
            # assign symbol
            cursym = imginfo.getSymbol(curaddr)
            cursymoffset = None if cursym is None else curaddr - cursym._Addr
            
            # assign instruction
            curinst = None
            if (cursecname == ".text") or (cursecname == ".plt"):
                curinst = imginfo.getInstruction(curaddr)
            if curinst is not None:
                offsetsize[curoffset] = curinst[0]
            
            # store
            if (cursym is None) and (curinst is None):
                outputstring[curoffset] = \
                  ("  0x%08x:\t\tCorr.: %7.4f\t\tSection: %-15s" % \
                  (curoffset, curcoeff, cursecname))
            elif (cursym is not None) and (curinst is None):
                outputstring[curoffset] = \
                  ("  0x%08x:\t\tCorr.: %7.4f\t\tSection: %-15s Symbol: %-30s / 0x%08x" % \
                  (curoffset, curcoeff, cursecname, cursym._Name, cursymoffset))
            elif (cursym is None) and (curinst is not None):
                outputstring[curoffset] = \
                  ("  0x%08x:\t\tCorr.: %7.4f\t\tSection: %-15s Symbol: %-30s / %-10s\t\tInstr. (len=%02d):\t%s" % \
                  (curoffset, curcoeff, cursecname, '-', '-', curinst[0], curinst[1]))
            else:
                outputstring[curoffset] = \
                  ("  0x%08x:\t\tCorr.: %7.4f\t\tSection: %-15s Symbol: %-30s / 0x%08x\t\tInstr. (len=%02d):\t%s" % \
                  (curoffset, curcoeff, cursecname, cursym._Name, cursymoffset, curinst[0], curinst[1]))
            
            # count
            numleaks += 1
    
    # infos
    print ("Active Instructions: %d" % len(meas._ImageData[i]))
    print ("Detected Leaks: %d (%.2f%% of active)" % \
           (numleaks, (numleaks * 100) / len(meas._ImageData[i])))
    print ("")
    if numleaks > 0:
        pkeys = list(sorted(outputstring.keys()))
        for i in range(0, len(outputstring)):
            print (outputstring[pkeys[i]])
    
    # separator
    print ("")
    print ("")

# exit
sys.exit()
# @endcond

