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

// Chaffing-and-Winnowing.
//
// This package implements Chaffing-and-Winnowing technology
// (http://people.csail.mit.edu/rivest/chaffing-980701.txt).
//
// It outputs two Poly1305 MACs for each bit of input data: one valid,
// and other is not. MACs sequence is following:
//
//     MAC of 1st byte, 1st bit, 0 possible value
//     MAC of 1st byte, 1st bit, 1 possible value
//     MAC of 1st byte, 2nd bit, 0 possible value
//     MAC of 1st byte, 2nd bit, 1 possible value
//     ...
//
// If bit value is 0, then first MAC is taken over "1" and the second
// one is over "0". If bit value is 1, then first is taken over "0" and
// second is over "1".
//
// Poly1305 uses 256-bit one-time key. We generate it using XSalsa20 for
// for the whole byte at once (16 MACs).
//
//     MACKey1, MACKey2, ... = XSalsa20(authKey, nonce, 0x00...)
//     nonce = prefix || 0x00... || big endian byte number
package cnw

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"
)

const (
	EnlargeFactor = 16 * poly1305.TagSize
)

func zero(in []byte) {
	for i := 0; i < len(in); i++ {
		in[i] = 0
	}
}

// Chaff the data. noncePrfx is 64-bit nonce. Output data will be much
// larger: 256 bytes for each input byte.
func Chaff(authKey *[32]byte, noncePrfx, in []byte) []byte {
	out := make([]byte, len(in)*EnlargeFactor)
	keys := make([]byte, 8*64)
	nonce := make([]byte, 24)
	copy(nonce[:8], noncePrfx)
	var i int
	var v byte
	tag := new([16]byte)
	macKey := new([32]byte)
	for n, b := range in {
		binary.BigEndian.PutUint64(nonce[16:], uint64(n))
		salsa20.XORKeyStream(keys, keys, nonce, authKey)
		for i = 0; i < 8; i++ {
			v = (b >> uint8(i)) & 1
			copy(macKey[:], keys[64*i:64*i+32])
			if v == 0 {
				poly1305.Sum(tag, []byte("1"), macKey)
			} else {
				poly1305.Sum(tag, []byte("0"), macKey)
			}
			copy(out[16*(n*16+i*2):], tag[:])
			copy(macKey[:], keys[64*i+32:64*i+64])
			if v == 1 {
				poly1305.Sum(tag, []byte("1"), macKey)
			} else {
				poly1305.Sum(tag, []byte("0"), macKey)
			}
			copy(out[16*(n*16+i*2+1):], tag[:])
		}
		zero(keys)
	}
	zero(macKey[:])
	return out
}

// Winnow the data.
func Winnow(authKey *[32]byte, noncePrfx, in []byte) ([]byte, error) {
	if len(in)%EnlargeFactor != 0 {
		return nil, errors.New("Invalid data size")
	}
	out := make([]byte, len(in)/EnlargeFactor)
	keys := make([]byte, 8*64)
	nonce := make([]byte, 24)
	copy(nonce[:8], noncePrfx)
	var i int
	var v byte
	tag := new([16]byte)
	macKey := new([32]byte)
	defer zero(macKey[:])
	var is01 bool
	var is00 bool
	var is11 bool
	var is10 bool
	for n := 0; n < len(out); n++ {
		binary.BigEndian.PutUint64(nonce[16:], uint64(n))
		salsa20.XORKeyStream(keys, keys, nonce, authKey)
		v = 0
		for i = 0; i < 8; i++ {
			copy(macKey[:], keys[64*i:64*i+32])
			poly1305.Sum(tag, []byte("1"), macKey)
			is01 = subtle.ConstantTimeCompare(
				tag[:],
				in[16*(n*16+i*2):16*(n*16+i*2+1)],
			) == 1
			poly1305.Sum(tag, []byte("0"), macKey)
			is00 = subtle.ConstantTimeCompare(
				tag[:],
				in[16*(n*16+i*2):16*(n*16+i*2+1)],
			) == 1
			copy(macKey[:], keys[64*i+32:64*i+64])
			poly1305.Sum(tag, []byte("1"), macKey)
			is11 = subtle.ConstantTimeCompare(
				tag[:],
				in[16*(n*16+i*2+1):16*(n*16+i*2+2)],
			) == 1
			poly1305.Sum(tag, []byte("0"), macKey)
			is10 = subtle.ConstantTimeCompare(
				tag[:],
				in[16*(n*16+i*2+1):16*(n*16+i*2+2)],
			) == 1
			if !((is01 && is10) || (is00 && is11)) {
				zero(keys)
				return nil, errors.New("Invalid authenticator received")
			}
			if is11 {
				v = v | 1<<uint8(i)
			}
		}
		out[n] = v
		zero(keys)
	}
	return out, nil
}
