// This file contains RSA portability wrappers.

#include "goboringcrypto.h"

// Both in OpenSSL 1.1 and BoringSSL.
void
_goboringcrypto_RSA_get0_key(const GO_RSA *rsa,
			     const GO_BIGNUM **n, const GO_BIGNUM **e,
			     const GO_BIGNUM **d)
{
  if (n)
    *n = rsa->n;
  if (e)
    *e = rsa->e;
  if (d)
    *d = rsa->d;
}

// Both in OpenSSL 1.1 and BoringSSL.
void
_goboringcrypto_RSA_get0_factors(const GO_RSA *rsa,
				 const GO_BIGNUM **p, const GO_BIGNUM **q)
{
  if (p)
    *p = rsa->p;
  if (q)
    *q = rsa->q;
}

// Both in OpenSSL 1.1 and BoringSSL.
void
_goboringcrypto_RSA_get0_crt_params(const GO_RSA *rsa,
				    const GO_BIGNUM **dmp1,
				    const GO_BIGNUM **dmp2,
				    const GO_BIGNUM **iqmp)
{
  if (dmp1)
    *dmp1 = rsa->dmp1;
  if (dmp2)
    *dmp2 = rsa->dmq1; // Not dmp2.
  if (iqmp)
    *iqmp = rsa->iqmp;
}

// Only in BoringSSL.
int
_goboringcrypto_RSA_verify_raw(GO_RSA *rsa, size_t *out_len, uint8_t *out,
				 size_t max_out,
				 const uint8_t *in, size_t in_len, int padding)
{
  if (padding != GO_RSA_PKCS1_PADDING
      || max_out < RSA_size(rsa))
    return 0;
  int ret = RSA_public_decrypt (in_len, in, out, rsa, RSA_NO_PADDING);
  if (ret <= 0)
    return 0;
  *out_len = ret;
  return 1;
}

