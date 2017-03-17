#!/usr/bin/python3

##
# @package report.tonumpy
# @file tonumpy.py
# @brief Convert measurements of the instrcnt Pintool to Numpy format.
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
from instrcnt import Measurements

"""
*************************************************************************
"""

##
# Program help text.
#
DOC = """
usage:
   tonumpy [options] [INSTRCNT_FILE] [EXPONENT_FILE]

options:
     -k, --keysize=INTEGER       size of key in bits
     -o, --destfile=PATH         destination file path
"""

"""
*************************************************************************
"""

# @cond IGNORE
# get cmd line arguments
cmdargs = docopt.docopt(DOC, version='tonumpy 0.1')
if (None in cmdargs.values()):
    print (DOC)
    sys.exit()

# arguments
mfile = os.path.expanduser(os.path.expandvars(cmdargs['INSTRCNT_FILE']))
kfile = os.path.expanduser(os.path.expandvars(cmdargs['EXPONENT_FILE']))
ksizebits = int(cmdargs['--keysize'])
ksizebytes = int(ksizebits / 8)
outpath = os.path.expanduser(os.path.expandvars(cmdargs['--destfile']))

# convert
meas = Measurements()
meas.parse(ksizebytes, mfile, kfile)
meas.save(outpath)

# exit
sys.exit()
# @endcond

