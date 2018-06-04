#include "goboringcrypto.h"

void
_goboringcrypto_EVP_AES_cbc_encrypt(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t len, const int enc)
{
	if (enc)
		EVP_AES_cbc_enc(ctx, in, out, len);
	else
		EVP_AES_cbc_dec(ctx, in, out, len);
}

void
EVP_AES_cbc_enc(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t in_len)
{
	int len;
	EVP_EncryptUpdate(ctx, out, &len, in, in_len);
}

void
EVP_AES_cbc_dec(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t in_len)
{
	int len;
	EVP_DecryptUpdate(ctx, out, &len, in, in_len);
}
