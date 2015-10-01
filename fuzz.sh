#!/bin/sh

set -e
afl-clang -lssl -lcrypto -o pem2bignum pem2bignum.c -Wall -Wextra -Werror -pedantic
afl-fuzz -i indir -o outdir -f key.pub -- ./pem2bignum key.pub
