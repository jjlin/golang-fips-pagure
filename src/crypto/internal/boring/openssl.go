// +build linux
// +build !android
// +build !no_openssl
// +build !cmd_go_bootstrap
// +build !msan

package boring

// #include "goboringcrypto.h"
// #cgo LDFLAGS: -ldl
import "C"
import (
	"crypto/internal/boring/fipstls"
	"crypto/internal/boring/sig"
	"errors"
	"os"
	"runtime"
	"strings"
)

const (
	fipsOn  = C.int(1)
	fipsOff = C.int(0)
)

func opensslInit() {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// Check if we can `dlopen` OpenSSL
	if C._goboringcrypto_DLOPEN_OPENSSL() == C.NULL {
		return
	}

	// Initialize the OpenSSL library.
	C._goboringcrypto_OPENSSL_setup()

	// Check to see if the system is running in FIPS mode, if so
	// enable "boring" mode to call into OpenSSL for FIPS compliance.
	if fipsModeEnabled() {
		enableBoringFIPSMode()
	}
	sig.BoringCrypto()
}

func enableBoringFIPSMode() {
	Enabled = true

	if C._goboringcrypto_OPENSSL_thread_setup() != 1 {
		panic("boringcrypto: OpenSSL thread setup failed")
	}
	fipstls.Force()
}

func fipsModeEnabled() bool {
	return os.Getenv("GOLANG_FIPS") == "1" ||
		C._goboringcrypto_FIPS_mode() == fipsOn
}

var randstub bool

func RandStubbed() bool {
	return randstub
}

func StubOpenSSLRand() {
	if !randstub {
		randstub = true
		C._goboringcrypto_stub_openssl_rand()
	}
}

func RestoreOpenSSLRand() {
	if randstub {
		randstub = false
		C._goboringcrypto_restore_openssl_rand()
	}
}

func PanicIfStrictFIPS(msg string) {
	if os.Getenv("GOLANG_STRICT_FIPS") == "1" || strictFIPS {
		panic(msg)
	}
}

func NewOpenSSLError(msg string) error {
	var b strings.Builder
	var e C.ulong

	b.WriteString(msg)
	b.WriteString("\nopenssl error(s):\n")

	for {
		e = C._goboringcrypto_internal_ERR_get_error()
		if e == 0 {
			break
		}
		var buf [256]byte
		C._goboringcrypto_internal_ERR_error_string_n(e, base(buf[:]), 256)
		b.Write(buf[:])
		b.WriteByte('\n')
	}
	return errors.New(b.String())
}

