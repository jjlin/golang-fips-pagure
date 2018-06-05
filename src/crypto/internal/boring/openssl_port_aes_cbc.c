#include "goboringcrypto.h"

void
_goboringcrypto_EVP_AES_cbc_encrypt(EVP_CIPHER_CTX *ctx, const uint8_t *in, uint8_t *out, size_t in_len, const int enc)
{
	int outlen;
	EVP_CipherUpdate(ctx, out, &outlen, in, in_len);
	//EVP_CipherFinal_ex(ctx, out, &outlen);
}

