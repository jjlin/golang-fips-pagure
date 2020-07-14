// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

package boring

// #include "goboringcrypto.h"
/*
 */
import "C"
import (
	"math/big"
	"unsafe"
)

type ECKey struct {
	X, Y, D *big.Int
	Priv *C.GO_EC_KEY
}

func GenerateKeyEC(curve string) (*ECKey, error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}
	key := C._goboringcrypto_EC_KEY_new_by_curve_name(nid)
	if key == nil {
		return nil, NewOpenSSLError("EC_KEY_new_by_curve_name failed")
	}
	defer C._goboringcrypto_EC_KEY_free(key)
	if C._goboringcrypto_EC_KEY_generate_key(key) == 0 {
		return nil, NewOpenSSLError("EC_KEY_generate_key failed")
	}
	group := C._goboringcrypto_EC_KEY_get0_group(key)
	pt := C._goboringcrypto_EC_KEY_get0_public_key(key)
	bd := C._goboringcrypto_EC_KEY_get0_private_key(key)
	if pt == nil || bd == nil {
		return nil, NewOpenSSLError("EC_KEY_get0_private_key failed")
	}
	bx := C._goboringcrypto_BN_new()
	if bx == nil {
		return nil, NewOpenSSLError("BN_new failed")
	}
	defer C._goboringcrypto_BN_free(bx)
	by := C._goboringcrypto_BN_new()
	if by == nil {
		return nil, NewOpenSSLError("BN_new failed")
	}
	defer C._goboringcrypto_BN_free(by)
	if C._goboringcrypto_EC_POINT_get_affine_coordinates_GFp(group, pt, bx, by, nil) == 0 {
		return nil, NewOpenSSLError("EC_POINT_get_affine_coordinates_GFp failed")
	}
	eckey := &ECKey{
		X: bnToBig(bx),
		Y: bnToBig(by),
		D: bnToBig(bd),
	}
	return eckey, nil
}

func GenerateSharedKey(curve string, peerkey, pkey []byte) ([]byte, error) {
	nid, err := curveNID(curve)
	if err != nil {
		return nil, err
	}
	bpriv := new(big.Int)
	bpriv.SetBytes(pkey)
	bnpriv := bigToBN(bpriv)

	eckeyPriv := C._goboringcrypto_EC_KEY_new_by_curve_name(nid)
	if C._goboringcrypto_EC_KEY_set_private_key(eckeyPriv, bnpriv) != 1 {
		return nil, NewOpenSSLError("EC_KEY_set_private_key failed")
	}

	eckeyPeer := C._goboringcrypto_EC_KEY_new_by_curve_name(nid)
	ecgroup := C._goboringcrypto_EC_GROUP_new_by_curve_name(nid)
	ecpointPeer := C._goboringcrypto_EC_POINT_new(ecgroup)
	bnCtx := C._goboringcrypto_BN_CTX_new()
	defer C._goboringcrypto_BN_CTX_free(bnCtx)
	if C._goboringcrypto_EC_POINT_oct2point(ecgroup, ecpointPeer, (*C.uchar)(unsafe.Pointer(&peerkey[0])), C.size_t(len(peerkey)), bnCtx) != 1 {
		return nil, NewOpenSSLError("EC_POINT_oct2point failed")
	}
	if C._goboringcrypto_EC_KEY_set_public_key(eckeyPeer, ecpointPeer) != 1 {
		return nil, NewOpenSSLError("EC_KEY_set_public_key failed")
	}

	evpPriv := C._goboringcrypto_EVP_PKEY_new()
	if C._goboringcrypto_EVP_PKEY_set1_EC_KEY(evpPriv, eckeyPriv) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_set1_EC_KEY failed")
	}

	evpPeer := C._goboringcrypto_EVP_PKEY_new()
	if C._goboringcrypto_EVP_PKEY_set1_EC_KEY(evpPeer, eckeyPeer) != 1 {
		return nil, NewOpenSSLError("EVP_PKEY_set1_EC_KEY failed")
	}

	ctx := C._goboringcrypto_EVP_PKEY_CTX_new(evpPriv, nil)
	if ctx == nil {
		return nil, NewOpenSSLError("EVP_PKEY_CTX_new failed")
	}
	defer C._goboringcrypto_EVP_PKEY_CTX_free(ctx)

	if 1 != C._goboringcrypto_EVP_PKEY_derive_init(ctx) {
		return nil, NewOpenSSLError("EVP_PKEY_derive_init failed")
	}
	if 1 != C._goboringcrypto_EVP_PKEY_derive_set_peer(ctx, evpPeer) {
		return nil, NewOpenSSLError("EVP_PKEY_derive_set_peer failed")
	}

	var secretLen C.size_t
	/* Determine buffer length for shared secret */
	if 1 != C._goboringcrypto_EVP_PKEY_derive(ctx, nil, &secretLen) {
		return nil, NewOpenSSLError(("EVP_PKEY_derive failed"))
	}

	secret := make([]byte, int(secretLen))

	/* Derive the shared secret */
	if 1 != C._goboringcrypto_EVP_PKEY_derive(ctx, (*C.uchar)(unsafe.Pointer(&secret[0])), &secretLen) {
		return nil, NewOpenSSLError("EVP_PKEY_derive failed")
	}

	return secret, nil
}
