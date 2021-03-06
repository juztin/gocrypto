// Copyright 2009 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// This file is dervied from the RC4 test code by Google,
// in an effort to maintain consistant code.
// This file can be found at:
//     http://golang.org/src/pkg/crypto/rc4/rc4_test.go

package rc2

import (
	"crypto/cipher"
	"fmt"
	"testing"
)

type rc2Test struct {
	key, plaintext, ciphertext []byte
}

// Below data is from RFC-2268 doc (https://tools.ietf.org/html/rfc2268)
var golden = []rc2Test{
	{
		[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		[]byte{0xeb, 0xb7, 0x73, 0xf9, 0x93, 0x27, 0x8e, 0xff},
	},
	{
		[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		[]byte{0x27, 0x8b, 0x27, 0xe4, 0x2e, 0x2f, 0x0d, 0x49},
	},
	{
		[]byte{0x30, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		[]byte{0x10, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x01},
		[]byte{0x30, 0x64, 0x9e, 0xdf, 0x9b, 0xe7, 0xd2, 0xc2},
	},
	{
		[]byte{0x88, 0xbc, 0xa9, 0x0e, 0x90, 0x87, 0x5a, 0x7f, 0x0f, 0x79, 0xc3, 0x84, 0x62, 0x7b, 0xaf, 0xb2},
		[]byte{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0},
		[]byte{0x22, 0x69, 0x55, 0x2a, 0xb0, 0xf8, 0x5c, 0xa6},
	},
}

func testEncrypt(t *testing.T, desc string, b cipher.Block, enc, expect []byte) {
	for i, v := range enc {
		if v != expect[i] {
			t.Fatalf("%s: mismatch at byte %d:\nhave %x\nwant %x", desc, i, enc, expect)
		}
	}
}

func TestGolden(t *testing.T) {
	for gi, g := range golden {
		c, err := NewCipher(g.key)
		if err != nil {
			t.Fatalf("#%d: NewCipher: %v", gi, err)
		}

		dst := make([]byte, len(g.plaintext))
		c.Encrypt(dst, g.plaintext)

		off := 0
		for off < len(g.plaintext) {
			n := len(g.plaintext) - off
			desc := fmt.Sprintf("#%d@[%d:%d]", gi, off, off+n)
			testEncrypt(t, desc, c, dst, g.ciphertext)
			off += n
		}
	}
}

func benchmark(b *testing.B, size, gi int32) {
	c, err := NewCipher(golden[gi].key)
	if err != nil {
		panic(err)
	}
	dst := make([]byte, size)
	for i := 0; i < b.N; i++ {
		c.Encrypt(dst, golden[gi].plaintext)
	}
}

func BenchmarkRC2_8(b *testing.B) {
	benchmark(b, 8, 0)
}

func BenchmarkRC2_16(b *testing.B) {
	benchmark(b, 16, 3)
}
