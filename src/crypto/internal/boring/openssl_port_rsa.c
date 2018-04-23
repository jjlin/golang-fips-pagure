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

// Only in BoringSSL.
int
 _goboringcrypto_RSA_generate_key_fips(GO_RSA *rsa, int size, GO_BN_GENCB *cb)
{
  // BoringSSL's RSA_generate_key_fips hard-codes e to 65537.
  BIGNUM *e = BN_new();
  if (e == NULL)
    return 0;
  int ret = BN_set_word(e, RSA_F4)
    && RSA_generate_key_ex(rsa, size, e, cb);
  BN_free(e);
  return ret;
}

// Only in BoringSSL.
int _goboringcrypto_RSA_sign_raw(GO_RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                 const uint8_t *in, size_t in_len, int padding) {
  // NOTE(deparker) BoringSSL RSA interface includes the method `rsa->meth->sign_raw`. This is
  // not implemented in OpenSSL, nor is it used in the Go caller. See {BoringSSL}/crypto/fipsmodule/rsa/rsa.c:283
  // for an example usage.

  return rsa_default_sign_raw(rsa, out_len, out, max_out, in, in_len, padding);
}

// Only in BoringSSL.
int rsa_default_sign_raw(GO_RSA *rsa, size_t *out_len, uint8_t *out,
                         size_t max_out, const uint8_t *in, size_t in_len,
                         int padding) {
	EVP_PKEY *pkey = EVP_PKEY_new();
	EVP_PKEY_assign_RSA(pkey, rsa);
        EVP_PKEY_CTX *ctx;
	size_t siglen;
	int ret;

        ctx = EVP_PKEY_CTX_new(pkey, NULL /* no engine */);
        if (!ctx) {
		ret = 0;
		goto err;
	}
        if (EVP_PKEY_sign_init(ctx) <= 0) {
		ret = 0;
		goto err;
	}

	switch(padding) {
	// No padding is acceptable in this sign raw function because it is
	// called from other functions that may have already set the padding.
	case GO_RSA_NO_PADDING:
	case GO_RSA_PKCS1_PADDING:
		if (EVP_PKEY_CTX_set_rsa_padding(ctx, padding) <= 0) {
			ret = 0;
			goto err;
		}
		break;
	default:
		ret = 0;
		goto err;
	}

        /* Determine buffer length */
        if (EVP_PKEY_sign(ctx, NULL, &siglen, in, in_len) <= 0) {
		ret = 0;
		goto err;
	}
	if (max_out < siglen) {
		ret = 0;
		goto err;
	}

        if (EVP_PKEY_sign(ctx, out, out_len, in, in_len) <= 0)
		ret = 0;

err:
	EVP_PKEY_CTX_free(ctx);
	return ret;
}

int _goboringcrypto_RSA_sign_pss_mgf1(RSA *rsa, size_t *out_len, uint8_t *out, size_t max_out,
                      const uint8_t *in, size_t in_len, const EVP_MD *md,
                      const EVP_MD *mgf1_md, int salt_len) {
  if (in_len != EVP_MD_size(md)) {
    return 0;
  }

  size_t padded_len = RSA_size(rsa);
  uint8_t *padded = OPENSSL_malloc(padded_len);
  if (padded == NULL) {
    return 0;
  }

  int ret =
      RSA_padding_add_PKCS1_PSS_mgf1(rsa, padded, in, md, mgf1_md, salt_len) &&
      _goboringcrypto_RSA_sign_raw(rsa, out_len, out, max_out, padded, padded_len,
                   RSA_NO_PADDING);
  OPENSSL_free(padded);
  return ret;
}

int _goboringcrypto_RSA_verify_pss_mgf1(RSA *rsa, const uint8_t *msg, size_t msg_len,
                        const EVP_MD *md, const EVP_MD *mgf1_md, int salt_len,
                        const uint8_t *sig, size_t sig_len) {
  if (msg_len != EVP_MD_size(md)) {
    return 0;
  }

  size_t em_len = RSA_size(rsa);
  uint8_t *em = OPENSSL_malloc(em_len);
  if (em == NULL) {
    return 0;
  }

  int ret = 0;
  if (!_goboringcrypto_RSA_verify_raw(rsa, &em_len, em, em_len, sig, sig_len, RSA_NO_PADDING)) {
    goto err;
  }

  if (em_len != RSA_size(rsa)) {
    goto err;
  }

  ret = RSA_verify_PKCS1_PSS_mgf1(rsa, msg, md, mgf1_md, em, salt_len);

err:
  OPENSSL_free(em);
  return ret;
}
