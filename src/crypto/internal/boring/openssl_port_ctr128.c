#include "goboringcrypto.h"

void
_goboringcrypto_EVP_AES_ctr128_enc(const uint8_t* in, uint8_t* out, size_t in_len, const uint8_t* key, size_t key_len, uint8_t* iv, uint8_t* ecount_buf, unsigned int* num)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	
	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) 
		goto err;
	
	switch (key_len) {
		case 128:
			if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
				goto err;
			break;
		case 192:
			if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_ctr(), NULL, key, iv))
				goto err;
			break;
		case 256:
			if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, iv))
				goto err;
	}
	
	/* Provide the message to be encrypted, and obtain the encrypted output.
	 * EVP_EncryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_EncryptUpdate(ctx, out, &len, in, in_len))
		goto err;
	
	/* Finalise the encryption. Further ciphertext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_EncryptFinal_ex(ctx, out + len, &len))
		goto err;
	
err:
	EVP_CIPHER_CTX_free(ctx);
}
