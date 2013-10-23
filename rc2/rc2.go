// Package rc2 implements RC2 encryption, as defined in Bruce Schneier's
// Applied Cryptography.
package rc2

// IMPORTANT: This package's sole use is for legacy support. RC2 should NOT be used
// in new projects for encryption.

import (
	"crypto/cipher"
	"strconv"
)

// A Cipher is an instance of RC2 (ARC2)
type Cipher struct {
	k []uint16
}

type KeySizeError int

func (k KeySizeError) Error() string {
	return "crypto/rc2: invalid key size " + strconv.Itoa(int(k))
}

// NewCipher creates and returns a new Cipher.  The key argument should be the
// RC2 key, at least 8 bytes at most 128 bytes.
func NewCipher(key []byte) (cipher.Block, error) {
	t := len(key)
	if t < 8 || t > 128 {
		return nil, KeySizeError(t)
	}

	c := &Cipher{make([]uint16, 64, 64)}
	expandKey(key, c.k)

	return c, nil
}

// Block size of 8 bytes
func (c *Cipher) BlockSize() int {
	return 8
}

// Encrypts a block, 8 bytes, of data
func (c *Cipher) Encrypt(dst, src []byte) {
	encryptBlock(c.k, dst, src)
}

// Decrypts a block, 8 bytes, of data
func (c *Cipher) Decrypt(dst, src []byte) {
	decryptBlock(c.k, dst, src)
}
