package boring

import "crypto"

// SignerOpts exists to signal that we are passing the
// hash in but the messages is not the digest.
type SignerOpts struct {
	crypto.SignerOpts
}

