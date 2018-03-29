// This file contains a port of the BoringSSL AEAD interface.

#include "goboringcrypto.h"

int _goboringcrypto_EVP_CIPHER_CTX_seal(
		int tls, uint8_t *out, uint8_t *nonce,
		uint8_t *aad, size_t aad_len,
		uint8_t *plaintext, size_t plaintext_len,
		size_t *ciphertext_len, uint8_t *key, int key_size) {

	EVP_CIPHER_CTX *ctx;
	int len;

	// Create and initialise the context.
	if(!(ctx = EVP_CIPHER_CTX_new())) return 0;

	switch(key_size) {
		case 128:
			if (tls) {
				// TODO(deparker) Is there anything different to do here?
				// Since we're not using the AEAD interface, the differences
				// may actually come later during SEAL / OPEN.
				// aead = C._goboringcrypto_EVP_aead_aes_128_gcm_tls12()
			} else {
				if (!EVP_EncryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
					return 0;
				}
			}
			break;
		case 256:
			if (tls) {
				// TODO(deparker) Is there anything different to do here?
				// Since we're not using the AEAD interface, the differences
				// may actually come later during SEAL / OPEN.
				// aead = C._goboringcrypto_EVP_aead_aes_128_gcm_tls12()
			} else {
				if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
					return 0;
				}
			}
			break;
	}


	// Initialize nonce.
	if (!EVP_EncryptInit_ex(ctx, NULL, NULL, NULL, nonce)) {
		return 0;
	}

	// Provide AAD data.
	if (!EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len)) {
		return 0;
	}

	if (!EVP_EncryptUpdate(ctx, out, &len, plaintext, plaintext_len)) {
		return 0;
	}
	*ciphertext_len = len;

	if (!EVP_EncryptFinal_ex(ctx, out + len, &len)) {
		return 0;
	}
	*ciphertext_len += len;

	if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, out+(*ciphertext_len))) {
		return 0;
	}

	EVP_CIPHER_CTX_free(ctx);

	return 1;
}

int _goboringcrypto_EVP_CIPHER_CTX_open(
		int tls, uint8_t *ciphertext, int ciphertext_len,
		uint8_t *aad, int aad_len,
		uint8_t *tag, unsigned char *key, int key_size,
		uint8_t *nonce, int nonce_len,
		uint8_t *plaintext, size_t *plaintext_len) {

	EVP_CIPHER_CTX *ctx;
	int len;
	int ret;

	// Create and initialise the context.
	if(!(ctx = EVP_CIPHER_CTX_new())) return 0;

	switch(key_size) {
		case 128:
			if (tls) {
				// TODO(deparker) Is there anything different to do here?
				// Since we're not using the AEAD interface, the differences
				// may actually come later during SEAL / OPEN.
				// aead = C._goboringcrypto_EVP_aead_aes_128_gcm_tls12()
			} else {
				if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_gcm(), NULL, NULL, NULL)) {
					return 0;
				}
			}
			break;
		case 256:
			if (tls) {
				// TODO(deparker) Is there anything different to do here?
				// Since we're not using the AEAD interface, the differences
				// may actually come later during SEAL / OPEN.
				// aead = C._goboringcrypto_EVP_aead_aes_128_gcm_tls12()
			} else {
				if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL)) {
					return 0;
				}
			}
			break;
	}

	// Initialize key and nonce.
	if(!EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce)) return 0;

	// Provide any AAD data.
	if(!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len))
		return 0;

	// Provide the message to be decrypted, and obtain the plaintext output.
	if(!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
		return 0;
	*plaintext_len = len;

	// Set expected tag value. Works in OpenSSL 1.0.1d and later.
	if(!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, tag))
		return 0;

	// Finalise the decryption. A positive return value indicates success,
	// anything else is a failure - the plaintext is not trustworthy.
	ret = _goboringcrypto_EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

	EVP_CIPHER_CTX_free(ctx);

	if(ret > 0) {
		// Success
		*plaintext_len += len;
		return 1;
	} else {
		// Verify failed
		return 0;
	}
}
