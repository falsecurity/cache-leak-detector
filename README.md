# Cache Leak Detector

This tool allows to detect instruction cache leaks in modular exponentiation
software with instruction-level granularity. It is based on a simple, yet
effective leakage test, which captures linear relations between the Hamming
weight of the exponent and the number of executions per instruction. To obtain
the instruction executions, the exponentiation software is monitored during
runtime using dynamic binary instrumentation (DBI).

In its current version, the **cache leak detector** can be used to find leaking
instructions in any modular exponentiation implementation (as long as an
interface is provided). For example, the tool allows to test RSA, DSA or
Diffie-Hellman key exchange implementations for instruction cache leaks. The
paper [Automated Detection of Instruction Cache Leaks in Modular Exponentiation
Software](./paper/cardis2016.pdf) provides a comprehensive leakage analysis of
RSA implementations found in widely used cryptographic libraries. The analysis
includes <a href="https://boringssl.googlesource.com/boringssl/"
target="_blank">BoringSSL</a>,
<a href="https://www.cs.auckland.ac.nz/~pgut001/cryptlib/"
target="_blank">cryptlib</a>, 
<a href="https://www.gnu.org/software/libgcrypt/" target="_blank">Libgcrypt</a>, 
<a href="https://www.libressl.org/" target="_blank">LibreSSL</a>,
<a href="http://www.matrixssl.org/" target="_blank">MatrixSSL</a>, 
<a href="https://tls.mbed.org/" target="_blank">mbed TLS</a>, 
<a href="https://www.lysator.liu.se/~nisse/nettle/" target="_blank">Nettle</a>, 
<a href="https://www.openssl.org/" target="_blank">OpenSSL</a>, and
<a href="https://wolfssl.com/" target="_blank">wolfSSL</a>.

## Table of Contents

- [Tool Description](#tool-description)
- [Repository](#repository)
- [Dependencies](#dependencies)
- [Build](#build)
- [Example](#example)
- [Report](#report)
- [Discussion](#discussion)
- [Securing Software](#securing-software)
- [Feedback](#feedback)
- [License](#license)
- [References](#references)

## Tool Description

The **cache leak detector** has a modular architecture. It consists of a
[target](./target) program, an extension to Intel's DBI framework *Pin*, called
[pintool](./pintool), and [report](./report) scripts.

The target program is implemented in C and interfaces a self-written RSA
decryption function (called [simplersa](./target/simplersa.c)) that uses the
<a href="https://git.io/vy9Px" target="_blank">`BIGNUM`</a> library within
OpenSSL. In every execution it triggers one decryption in a dedicated thread.
Everything within this thread is instrumented, while preparation and clean-up
tasks executed by the main thread are omitted. This improves the measurement
quality for the leakage test. The target program writes the exponents used
during decryption to an output file, which must be passed to the report scripts.
Note that the target program can be extended to interface any other
implementation of modular exponentiation or generally any other software that
should be tested for instruction cache or execution flow leaks.

<a href="https://software.intel.com/en-us/articles/pintool/"
target="_blank">Intel Pin</a> is used to instrument the target implementation
and count the number of executions for all active instructions. Extensions to
Intel Pin are commonly referred to as *pintools* and are written in C++. They can
access any of the instrumentation capabilities offered by Pin. To count the
number of executions per instruction, the currently implemented pintool tracks
the instruction pointer and maintains counters for all addresses within all
images that are loaded by the target program. In other words, *any* shared
library that is used by the target implementation is instrumented and hence all
leaks are captured. After the target program is done, the pintool writes all
non-zero counters together with infos about all loaded images to an output file.
This file must also be passed to the report scripts. Note that any other DBI
framework that supports tracking the instruction pointer can be used as well,
e.g., <a href="http://valgrind.org/" target="_blank">valgrind</a> or
<a href="http://dynamorio.org/" target="_blank">DynamoRIO</a>.

The report scripts parse the output files of the target program and the pintool,
perform the leakage test and report any leaking instructions. The scripts are
implemented in Python (version 3). The [tonumpy](./report/tonumpy.py) script
parses and merges the output files into one <a href="http://www.numpy.org/"
target="_blank">Numpy</a> file. This is done to save storage space, because
especially the output file of the pintool might grow to several MB and even GB.
After the conversion, the original output files are not needed anymore and can
be deleted. The [report](./report/report.py) script then reads the Numpy file
and calculates the leakage results for all instructions. An instruction is said
to *leak*, if its correlation coefficient is above the significance threshold.
This threshold depends on the confidence level with which the significance shall
be determined and the number of performed measurements. More details about the
threshold are given in the [paper](./paper/cardis2016.pdf). If an instruction
leaks, the report script tries to gather more information about it from the
image it is contained in. It uses <a href="https://github.com/eliben/pyelftools"
target="_blank">pyelftools</a> to retrieve symbol and section infos and
<a href="http://www.capstone-engine.org/" target="_blank">Capstone</a> to
disassemble the image and get instruction infos. Eventually, the report script
prints all leaking instructions and all gathered information about them.

So far, there is no complete understanding of how many bits of information a
leaking instruction reveals to an adversary that observes the instruction cache.
However, it is intuitively clear that any execution flow dependency on input
data should be avoided, if said input is sensitive or secret. Therefore it is
recommended to fix all leaks that the **cache leak detector** reports.

## Repository

|        Folder        |                        Description                           |
| -------------------- | ------------------------------------------------------------ |
| [doxygen](./doxygen) | HTML documentation of the source code                        |
| [example](./example) | Working directory of the example presented [below](#example) |
| [paper](./paper)     | Related publication at the <a href="https://2016.cardis.org/program.html" target="_blank">CARDIS 2016</a> conference |
| [pintool](./pintool) | Extension of the Pin DBI framework                           |
| [report](./report)   | Python scripts for post-processing and leakage reports       |
| [target](./target)   | Instrumentation target that executes RSA decryptions         |

## Dependencies

In order to use **cache leak detector** and generate its documentation, the
following software packages are required:

* GNU <a href="https://gcc.gnu.org/" target="_blank">Compiler Collection</a> and
  <a href="https://www.gnu.org/software/make/" target="_blank">Make</a>
* <a href="https://www.openssl.org/source/" target="_blank">OpenSSL</a> Source Code
  and Shared Library
* <a href="https://software.intel.com/en-us/articles/pintool-downloads"
  target="_blank">Intel Pin</a> Source Code and Binaries
* Python v3.x with packages:
  <a href="http://www.numpy.org/" target="_blank">numpy</a>,
  <a href="https://www.scipy.org/" target="_blank">scipy</a>,
  <a href="https://github.com/eliben/pyelftools" target="_blank">pyelftools</a>,
  <a href="http://www.capstone-engine.org/" target="_blank">capstone</a>, and
  <a href="http://docopt.org/" target="_blank">docopt</a>
* <a href="http://www.doxygen.org/" target="_blank">Doxygen</a>

Under Debian/Ubuntu, the following commands should simplify the installation
process:

```
sudo apt-get install build-essential
sudo apt-get install libssl1.0.0 libssl-dev
sudo apt-get install python3 python3-pip
sudo pip3 install numpy scipy capstone pyelftools docopt
sudo apt-get install doxygen
```

The current version of **cache leak detector** has been tested under Ubuntu
14.04 with gcc v4.8.4, Make v3.81, OpenSSL v1.0.1f, Pin v3.2, Python v3.4.3,
numpy v1.12.0, scipy v0.19.0, pyelftools v0.24, capstone v3.0.4, docopt v0.6.2,
and doxygen v1.8.6.

## Build

The entire project contains Makefiles that can be used to build the source code
and clean up the build files afterwards. By issuing

```
make
```

in the project root directory, the target program and the pintool extension are
compiled. Building the pintool requires that the source code directory of Pin is
available through an environment variable called `PIN_ROOT`.

The project documentation can be generated with doxygen by using the command

```
make doc
```

The documentation can subsequently be viewed in a web browser by opening the
index.html in the [doxygen](./doxygen) directory. All build and documentation
files are deleted with

```
make clean
```

Note that `PIN_ROOT` must also be defined when cleaning the build files of the
pintool.

## Example

The target program already contains an example implementation of RSA decryption.
It requires an existing RSA key file to avoid generating a new key for every
program run. Within this key the target program then replaces the existing
private exponent with a random one. An [example key](./example/2048bit.key) is
already included.

The Makefile in the project root directory implements additional commands for an
automated example run of the **cache leak detector**. To execute decryptions
and instrument the example implementation, type

```
make measure
```

Note that the Pin binary must be available under the command `pin`. To obtain
robust leakage results, multiple measurements should be done. To repeat the
measurement command N times, type

```
make measure loops=N
```

After taking a sufficient number of measurements, the output files of the target
program and the pintool can be converted to a Numpy file with

```
make convert
```

The final leakage results can be obtained from the Numpy file with

```
make report
```

The report is written to example/report.txt. All output files, including the
Numpy file, are also written to the [example](./example) directory. The executed
commands including all arguments can be viewed in the root directory
[Makefile](./Makefile).

Since the **cache leak detector** is designed to be run automatically, all of the
commands above can be executed in one run with

```
make detect
```

This will perform N = 10 measurements, followed by the Numpy conversion and the
report generation.

## Report

Currently, the generated report.txt displays leaking instructions in the
following way:

```
Significance Threshold: 0.9738

*************************************
Image: /lib/x86_64-linux-gnu/libcrypto.so.1.0.0
Active Instructions: 3468
Detected Leaks: 1426 (41.12% of active)

  0x0005e9f0:    Corr.:  0.9753    Section: .plt     Symbol: -          / -             Instr. (len=06):    jmp qword ptr [rip + 0x36e732]
  0x00095940:    Corr.:  0.9996    Section: .text    Symbol: BN_usub    / 0x00000110    Instr. (len=04):    sub rax, 8
  0x00095944:    Corr.:  0.9996    Section: .text    Symbol: BN_usub    / 0x00000114    Instr. (len=05):    cmp qword ptr [rax + 8], 0
  0x00095949:    Corr.:  0.9996    Section: .text    Symbol: BN_usub    / 0x00000119    Instr. (len=02):    jne 0x95950
```

This is an excerpt of the example report after `make detect`. The significance
threshold is printed at the beginning of the file. For each image the report
provides the file path, the number of active instructions during decryption, the
number of leaking instructions and their percentage of all active ones. For each
leaking instruction, the following properties are printed:

```
| Offset within Image | Corr. Coeff. | Image Section | Image Symbol | Offset within Symbol | Instr. Length | Instr. Disassembly |
| ------------------- | ------------ | ------------- | ------------ | -------------------- | ------------- | ------------------ |
| 0x00095949          | 0.9996       | .text         | BN_usub      | 0x00000119           | 02            | jne 0x95950        |
```

For any info that could not be retrieved from the image, a dash is printed.

## Discussion

When looking at the entire example report, it becomes obvious that the example
implementation exhibits massive instruction cache leaks. This is because it
relies on a square-and-multiply modular exponentiation algorithm, which by
design comes with substantial exponent-dependent execution flow variations.
Square-and-multiply as well as sliding window exponentiation (SWE) algorithms
are generally not recommended for security critical software, as both have
inherent execution flow dependencies. Better choices are
square-and-multiply-always, Montgomery ladder or fixed window exponentiation
(FWE) algorithms. Yet, a significant fraction of the cryptographic libraries
tested [here](./paper/cardis2016.pdf) still implements SWE algorithms.

With the example run of the **cache leak detector**, everyone can debunk the
vulnerable square-and-multiply implementation in about 30s (tested on an Intel
i7).

## Securing Software

The **cache leak detector** is intended to be used by anyone developing or
releasing security critical software. Its modular design and automated leakage
test facilitate the integration into existing development and release processes.

The analysis of cryptographic libraries in the [paper](./paper/cardis2016.pdf)
revealed an execution flow leak in wolfSSL v3.8.0, although the library
implements modular exponentiation using a Montgomery ladder. This clearly shows
that instruction cache leakage detection is important, even for software that
should be protected in theory. Experience simply shows that bugs can always be
introduced in practice.

As a response to the paper, wolfSSL fixed the leak in
<a href="https://git.io/vy9Mj" target="_blank">v3.10.0</a> and 
<a href="https://git.io/vy9i7" target="_blank">v3.10.2</a>. This is also
documented under
<a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-6076"
target="_blank">CVE-2017-6076</a>. In addition, MatrixSSL switched to a fixed
window exponentiation implementation in <a href="https://git.io/vy9v2"
target="_blank">v3.9.0</a>.

## Feedback

For questions, remarks, and bugs please use the contact information provided in
the [paper](./paper/cardis2016.pdf) or source code files. If you want to
contribute to **cache leak detector**, we always welcome ideas and improvements
of any kind.

## License

This project is released under the MIT [License](./LICENSE).

## References

* [1] <a href="https://dx.doi.org/10.1007/978-3-319-54669-8_14"
      target="_blank">Automated Detection of Instruction Cache Leaks in Modular
      Exponentiation Software - Andreas Zankl, Johann Heyszl, Georg Sigl</a>