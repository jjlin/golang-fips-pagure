#include "goboringcrypto.h"

void
_goboringcrypto_EVP_AES_cbc_encrypt(const uint8_t *in, uint8_t *out, size_t len, const uint8_t *key, size_t key_len, uint8_t *iv, const int enc)
{
	if (enc)
		EVP_AES_cbc_enc(in, out, len, key, key_len, iv);
	else
		EVP_AES_cbc_dec(in, out, len, key, key_len, iv);
}

void
EVP_AES_cbc_enc(const uint8_t *in, uint8_t *out, size_t in_len, const uint8_t *key, size_t key_len, uint8_t *iv)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	
	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new())) 
		goto err;
	
	switch (key_len) {
		case 128:
			if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
				goto err;
			break;
		case 192:
			if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv))
				goto err;
			break;
		case 256:
			if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
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

void
EVP_AES_cbc_dec(const uint8_t *in, uint8_t *out, size_t in_len, const uint8_t *key, size_t key_len, uint8_t *iv)
{
	EVP_CIPHER_CTX *ctx;
	int len;
	
	/* Create and initialise the context */
	if(!(ctx = EVP_CIPHER_CTX_new()))
		goto err;
	
	switch (key_len) {
		case 128:
			if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
				goto err;
			break;
		case 192:
			if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv))
				goto err;
			break;
		case 256:
			if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
				goto err;
	}
	
	/* Provide the message to be decrypted, and obtain the plaintext output.
	 * EVP_DecryptUpdate can be called multiple times if necessary
	 */
	if(1 != EVP_DecryptUpdate(ctx, out, &len, in, in_len))
		goto err;
	
	/* Finalise the decryption. Further plaintext bytes may be written at
	 * this stage.
	 */
	if(1 != EVP_DecryptFinal_ex(ctx, out + len, &len))
		goto err;
	
err:
	EVP_CIPHER_CTX_free(ctx);
}
