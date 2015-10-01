/* Copyright (C) 2015 Ben Wiederhake, 1995-1997 Eric Young (eay@cryptsoft.com)
 * I wish I could release this into Public Domain.
 *
 * Compile: gcc -lcrypt -lssl -o pem2bignum pem2bignum.c
 * [ Optional flags: -Wall -Wextra -Werror -pedantic ]
 * Usage: ./pem2bignum yourpemfile.pub > thenewfile.tglpub
 *
 * The format of the generated file is defined by libtgl
 * (https://github.com/vysheng/tgl), and thus *definitely doesn't* count as
 * derivative work. The contents of the generated file are a derivative work of
 * the input PEM file and the PEM format, and thus are also *not derivative work*
 * of OpenSSL.
 * I am not a patent lawyer, so don't mistake these hopes of mine as guarantees.
 *
 * The following should be the standard OpenSSL license,
 * copied from <openssl/pem.h>. Copyright of the typos
 * (e.g. "acknowledgement", "aheared", "publically", "rouines") are solely
 * (C) Eric Young.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <assert.h>
#include <stdio.h>

#include <openssl/err.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

void fwrite_ul (FILE *fp, unsigned long ul, const char *what) {
  unsigned char buf[4];
  buf[3] = (unsigned char) ((ul >>  0) & 0xFF);
  buf[2] = (unsigned char) ((ul >>  8) & 0xFF);
  buf[1] = (unsigned char) ((ul >> 16) & 0xFF);
  buf[0] = (unsigned char) ((ul >> 24) & 0xFF);
  if (!fwrite (buf, 4, 1, fp)) {
    fprintf (stderr, "Write failed: %s\n", what);
    exit (5);
  }
}

int main(int argc, char **argv) {
  /* Make him and his infectious license happy.
   * Use the opportunity to print versioning info. */
  fprintf (stderr, "This product includes cryptographic software written by"
          " Eric Young\n(eay@cryptsoft.com).\nCompiled against %s, linked"
          " against %s.\nThis is pem2bignum v0.1\n",
          OPENSSL_VERSION_TEXT, SSLeay_version(SSLEAY_VERSION));

  if (argc != 2) {
    fprintf (stderr, "Usage: %s yourpemfile.pub > thenewfile.tglpub\n", argv[0]);
    exit (1);
  }

  FILE *fp = fopen (argv[1], "rb");
  if (!fp) {
    fprintf (stderr, "Can't read file:\n%s\n", argv[1]);
    exit (2);
  }

  RSA *key = PEM_read_RSAPublicKey(fp, NULL, NULL, NULL);
  if (!key) {
    fprintf (stderr, "Doesn't look like valid PEM-RSA. OpenSSL says:\n");
    ERR_print_errors_fp (stderr);
    exit (3);
  }

  const int e_bits = BN_num_bits (key->e);
  const int n_bits = BN_num_bits (key->n);
  if (n_bits < 1023 // Allow "weak" 1024-bit keys
   || n_bits > 8192
   || e_bits < 4
   || e_bits > 31 // Should be 17, give or take one (e = 65537 is pretty common)
   || sizeof (int) < 4 /* Juuust to make sure. */) {
    char *hex_n = BN_bn2hex (key->n);
    char *hex_e = BN_bn2hex (key->e);
    fprintf (stderr, "Key has absurd sizes. Have a hexdump:\nn = %s\ne = %s\n",
             hex_n, hex_e);
    exit (4);
  }

  /* PART ONE: e, big endian 32 bit fixed length. */
  fwrite_ul (stdout, BN_get_word (key->e), "e (direct)");

  /* PART TWO: length of n in bytes, big endian 32 bit fixed length. */
  const int n_len = ((n_bits+7)/8); // Verbatim BN_num_bytes
  fwrite_ul (stdout, n_len, "n (length)");

  /* PART THREE: n, big endian, indicated-fixed length. */
  unsigned char *n_buf = malloc (n_len);
  if (!n_buf) {
    fprintf (stderr, "Huh? Out of memory?!\n");
    exit (6);
  }

  if (!BN_bn2bin (key->n, n_buf)) {
    fprintf (stderr, "Huh? BN_bn2bin failed?! OpenSSL says:\n");
    ERR_print_errors_fp (stderr);
    exit (7);
  }

  if (!fwrite (n_buf, n_len, 1, stdout)) {
    fprintf (stderr, "Write failed: n (raw)\n");
    exit (8);
  }

  if (ferror (stdout)) {
    fprintf (stderr, "stdout is in error state?!\n");
    exit (9);
  }

  /* Don't free anything, the OS will handle it.
   * However: Flush, in case anyone needs it. */
  fflush (stdout);

  return 0;
}
