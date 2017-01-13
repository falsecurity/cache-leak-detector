# cacheleaktool

This tool allows to detect instruction cache leaks in modular exponentiation software with instruction-level granularity. It is based on a simple and effective leakage test, which captures linear relations between the Hamming weight of the exponent and the number of executions per instruction. To obtain the instruction executions, the exponentiation software is observed during runtime with dynamic binary instrumentation.

In its first version, the tool can be used to find leaking instructions in any modular exponentiation implementation (as long as a wrapper is provided). For example, the tool allows to test RSA, DSA or ElGamal implementations for instruction cache leaks. A comprehensive leakage analysis of RSA implementations has been done for a number of widely used cryptographic libraries such as [OpenSSL](https://www.openssl.org/) (+ forks), [libgcrypt](https://www.gnu.org/software/libgcrypt/) and [wolfSSL](https://wolfssl.com/). The details and results can soon be obtained in the paper "Automated Detection of Instruction Cache Leaks in Modular Exponentiation Software", which has been presented at [CARDIS 2016](https://2016.cardis.org).

The code will be made available as soon as the paper is available to the public.
