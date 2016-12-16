/*
GoVPN -- simple secure free software virtual private network daemon
Copyright (C) 2014-2016 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

// All-Or-Nothing-Transform, based on OAEP.
//
// This package implements OAEP (Optimal Asymmetric Encryption Padding)
// (http://cseweb.ucsd.edu/~mihir/papers/oaep.html)
// used there as All-Or-Nothing-Transformation
// (http://theory.lcs.mit.edu/~cis/pubs/rivest/fusion.ps).
// We do not fix OAEP parts length, instead we add hash-based
// checksum like in SAEP+
// (http://crypto.stanford.edu/~dabo/abstracts/saep.html).
//
// AONT takes 128-bit random r, data M to be encoded and produce the
// package PKG:
//
//     PKG = P1 || P2
//      P1 = Salsa20(key=r, nonce=0x00, 0x00) XOR (M || BLAKE2b(r || M))
//      P2 = BLAKE2b(P1) XOR r
package aont

import (
	"crypto/subtle"
	"errors"

	"github.com/dchest/blake2b"
	"golang.org/x/crypto/salsa20"
)

const (
	HSize = 32
	RSize = 16
)

var (
	dummyNonce []byte = make([]byte, 8)
)

// Encode the data, produce AONT package. Data size will be larger than
// the original one for 48 bytes.
func Encode(r *[RSize]byte, in []byte) ([]byte, error) {
	out := make([]byte, len(in)+HSize+RSize)
	copy(out, in)
	h := blake2b.New256()
	h.Write(r[:])
	h.Write(in)
	copy(out[len(in):], h.Sum(nil))
	salsaKey := new([32]byte)
	copy(salsaKey[:], r[:])
	salsa20.XORKeyStream(out, out, dummyNonce, salsaKey)
	h.Reset()
	h.Write(out[:len(in)+32])
	for i, b := range h.Sum(nil)[:RSize] {
		out[len(in)+32+i] = b ^ r[i]
	}
	return out, nil
}

// Decode the data from AONT package. Data size will be smaller than the
// original one for 48 bytes.
func Decode(in []byte) ([]byte, error) {
	if len(in) < HSize+RSize {
		return nil, errors.New("Too small input buffer")
	}
	h := blake2b.New256()
	h.Write(in[:len(in)-RSize])
	salsaKey := new([32]byte)
	for i, b := range h.Sum(nil)[:RSize] {
		salsaKey[i] = b ^ in[len(in)-RSize+i]
	}
	h.Reset()
	h.Write(salsaKey[:RSize])
	out := make([]byte, len(in)-RSize)
	salsa20.XORKeyStream(out, in[:len(in)-RSize], dummyNonce, salsaKey)
	h.Write(out[:len(out)-HSize])
	if subtle.ConstantTimeCompare(h.Sum(nil), out[len(out)-HSize:]) != 1 {
		return nil, errors.New("Invalid checksum")
	}
	return out[:len(out)-HSize], nil
}
