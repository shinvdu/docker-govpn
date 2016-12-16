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

package govpn

import (
	"crypto/subtle"
	"encoding/binary"
	"io"
	"log"
	"time"

	"github.com/agl/ed25519"
	"github.com/agl/ed25519/extra25519"
	"github.com/dchest/blake2b"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/xtea"
)

const (
	RSize = 8
	SSize = 32
)

type Handshake struct {
	addr     string
	conn     io.Writer
	LastPing time.Time
	Conf     *PeerConf
	dsaPubH  *[ed25519.PublicKeySize]byte
	key      *[32]byte
	rNonce   *[RSize]byte
	dhPriv   *[32]byte    // own private DH key
	rServer  *[RSize]byte // random string for authentication
	rClient  *[RSize]byte
	sServer  *[SSize]byte // secret string for main key calculation
	sClient  *[SSize]byte
}

func keyFromSecrets(server, client []byte) *[SSize]byte {
	k := new([SSize]byte)
	for i := 0; i < SSize; i++ {
		k[i] = server[i] ^ client[i]
	}
	return k
}

// Zero handshake's memory state
func (h *Handshake) Zero() {
	if h.rNonce != nil {
		SliceZero(h.rNonce[:])
	}
	if h.dhPriv != nil {
		SliceZero(h.dhPriv[:])
	}
	if h.key != nil {
		SliceZero(h.key[:])
	}
	if h.dsaPubH != nil {
		SliceZero(h.dsaPubH[:])
	}
	if h.rServer != nil {
		SliceZero(h.rServer[:])
	}
	if h.rClient != nil {
		SliceZero(h.rClient[:])
	}
	if h.sServer != nil {
		SliceZero(h.sServer[:])
	}
	if h.sClient != nil {
		SliceZero(h.sClient[:])
	}
}

func (h *Handshake) rNonceNext(count uint64) []byte {
	nonce := make([]byte, RSize)
	nonceCurrent, _ := binary.Uvarint(h.rNonce[:])
	binary.PutUvarint(nonce, nonceCurrent+count)
	return nonce
}

func dhKeypairGen() (*[32]byte, *[32]byte) {
	priv := new([32]byte)
	pub := new([32]byte)
	repr := new([32]byte)
	reprFound := false
	for !reprFound {
		if _, err := Rand.Read(priv[:]); err != nil {
			log.Fatalln("Error reading random for DH private key:", err)
		}
		reprFound = extra25519.ScalarBaseMult(pub, repr, priv)
	}
	return priv, repr
}

func dhKeyGen(priv, pub *[32]byte) *[32]byte {
	key := new([32]byte)
	curve25519.ScalarMult(key, priv, pub)
	hashed := blake2b.Sum256(key[:])
	return &hashed
}

// Create new handshake state.
func NewHandshake(addr string, conn io.Writer, conf *PeerConf) *Handshake {
	state := Handshake{
		addr:     addr,
		conn:     conn,
		LastPing: time.Now(),
		Conf:     conf,
	}
	state.dsaPubH = new([ed25519.PublicKeySize]byte)
	copy(state.dsaPubH[:], state.Conf.Verifier.Pub[:])
	hashed := blake2b.Sum256(state.dsaPubH[:])
	state.dsaPubH = &hashed
	return &state
}

// Generate ID tag from client identification and data.
func idTag(id *PeerId, timeSync int, data []byte) []byte {
	ciph, err := xtea.NewCipher(id[:])
	if err != nil {
		panic(err)
	}
	enc := make([]byte, xtea.BlockSize)
	copy(enc, data)
	AddTimeSync(timeSync, enc)
	ciph.Encrypt(enc, enc)
	return enc
}

// Start handshake's procedure from the client. It is the entry point
// for starting the handshake procedure. // First handshake packet
// will be sent immediately.
func HandshakeStart(addr string, conn io.Writer, conf *PeerConf) *Handshake {
	state := NewHandshake(addr, conn, conf)
	var dhPubRepr *[32]byte
	state.dhPriv, dhPubRepr = dhKeypairGen()

	state.rNonce = new([RSize]byte)
	if _, err := Rand.Read(state.rNonce[:]); err != nil {
		log.Fatalln("Error reading random for nonce:", err)
	}
	var enc []byte
	if conf.Noise {
		enc = make([]byte, conf.MTU-xtea.BlockSize-RSize)
	} else {
		enc = make([]byte, 32)
	}
	copy(enc, dhPubRepr[:])
	if conf.Encless {
		var err error
		enc, err = EnclessEncode(state.dsaPubH, state.rNonce[:], enc)
		if err != err {
			panic(err)
		}
	} else {
		salsa20.XORKeyStream(enc, enc, state.rNonce[:], state.dsaPubH)
	}
	data := append(state.rNonce[:], enc...)
	data = append(data, idTag(state.Conf.Id, state.Conf.TimeSync, state.rNonce[:])...)
	state.conn.Write(data)
	return state
}

// Process handshake message on the server side.
// This function is intended to be called on server's side.
// If this is the final handshake message, then new Peer object
// will be created and used as a transport. If no mutually
// authenticated Peer is ready, then return nil.
func (h *Handshake) Server(data []byte) *Peer {
	// R + ENC(H(DSAPub), R, El(CDHPub)) + IDtag
	if h.rNonce == nil && ((!h.Conf.Encless && len(data) >= 48) ||
		(h.Conf.Encless && len(data) == EnclessEnlargeSize+h.Conf.MTU)) {
		h.rNonce = new([RSize]byte)
		copy(h.rNonce[:], data[:RSize])

		// Decrypt remote public key
		cDHRepr := new([32]byte)
		if h.Conf.Encless {
			out, err := EnclessDecode(
				h.dsaPubH,
				h.rNonce[:],
				data[RSize:len(data)-xtea.BlockSize],
			)
			if err != nil {
				log.Println("Unable to decode packet from", h.addr, err)
				return nil
			}
			copy(cDHRepr[:], out)
		} else {
			salsa20.XORKeyStream(
				cDHRepr[:],
				data[RSize:RSize+32],
				h.rNonce[:],
				h.dsaPubH,
			)
		}

		// Generate DH keypair
		var dhPubRepr *[32]byte
		h.dhPriv, dhPubRepr = dhKeypairGen()

		// Compute shared key
		cDH := new([32]byte)
		extra25519.RepresentativeToPublicKey(cDH, cDHRepr)
		h.key = dhKeyGen(h.dhPriv, cDH)

		var encPub []byte
		var err error
		if h.Conf.Encless {
			encPub = make([]byte, h.Conf.MTU)
			copy(encPub, dhPubRepr[:])
			encPub, err = EnclessEncode(h.dsaPubH, h.rNonceNext(1), encPub)
			if err != nil {
				panic(err)
			}
		} else {
			encPub = make([]byte, 32)
			salsa20.XORKeyStream(encPub, dhPubRepr[:], h.rNonceNext(1), h.dsaPubH)
		}

		// Generate R* and encrypt them
		h.rServer = new([RSize]byte)
		if _, err = Rand.Read(h.rServer[:]); err != nil {
			log.Fatalln("Error reading random for R:", err)
		}
		h.sServer = new([SSize]byte)
		if _, err = Rand.Read(h.sServer[:]); err != nil {
			log.Fatalln("Error reading random for S:", err)
		}
		var encRs []byte
		if h.Conf.Noise && !h.Conf.Encless {
			encRs = make([]byte, h.Conf.MTU-len(encPub)-xtea.BlockSize)
		} else if h.Conf.Encless {
			encRs = make([]byte, h.Conf.MTU-xtea.BlockSize)
		} else {
			encRs = make([]byte, RSize+SSize)
		}
		copy(encRs, append(h.rServer[:], h.sServer[:]...))
		if h.Conf.Encless {
			encRs, err = EnclessEncode(h.key, h.rNonce[:], encRs)
			if err != nil {
				panic(err)
			}
		} else {
			salsa20.XORKeyStream(encRs, encRs, h.rNonce[:], h.key)
		}

		// Send that to client
		h.conn.Write(append(encPub, append(
			encRs, idTag(h.Conf.Id, h.Conf.TimeSync, encPub)...,
		)...))
		h.LastPing = time.Now()
	} else
	// ENC(K, R+1, RS + RC + SC + Sign(DSAPriv, K)) + IDtag
	if h.rClient == nil && ((!h.Conf.Encless && len(data) >= 120) ||
		(h.Conf.Encless && len(data) == EnclessEnlargeSize+h.Conf.MTU)) {
		var dec []byte
		var err error
		if h.Conf.Encless {
			dec, err = EnclessDecode(
				h.key,
				h.rNonceNext(1),
				data[:len(data)-xtea.BlockSize],
			)
			if err != nil {
				log.Println("Unable to decode packet from", h.addr, err)
				return nil
			}
			dec = dec[:RSize+RSize+SSize+ed25519.SignatureSize]
		} else {
			dec = make([]byte, RSize+RSize+SSize+ed25519.SignatureSize)
			salsa20.XORKeyStream(
				dec,
				data[:RSize+RSize+SSize+ed25519.SignatureSize],
				h.rNonceNext(1),
				h.key,
			)
		}
		if subtle.ConstantTimeCompare(dec[:RSize], h.rServer[:]) != 1 {
			log.Println("Invalid server's random number with", h.addr)
			return nil
		}
		sign := new([ed25519.SignatureSize]byte)
		copy(sign[:], dec[RSize+RSize+SSize:])
		if !ed25519.Verify(h.Conf.Verifier.Pub, h.key[:], sign) {
			log.Println("Invalid signature from", h.addr)
			return nil
		}

		// Send final answer to client
		var enc []byte
		if h.Conf.Noise {
			enc = make([]byte, h.Conf.MTU-xtea.BlockSize)
		} else {
			enc = make([]byte, RSize)
		}
		copy(enc, dec[RSize:RSize+RSize])
		if h.Conf.Encless {
			enc, err = EnclessEncode(h.key, h.rNonceNext(2), enc)
			if err != nil {
				panic(err)
			}
		} else {
			salsa20.XORKeyStream(enc, enc, h.rNonceNext(2), h.key)
		}
		h.conn.Write(append(enc, idTag(h.Conf.Id, h.Conf.TimeSync, enc)...))

		// Switch peer
		peer := newPeer(
			false,
			h.addr,
			h.conn,
			h.Conf,
			keyFromSecrets(h.sServer[:], dec[RSize+RSize:RSize+RSize+SSize]))
		h.LastPing = time.Now()
		return peer
	} else {
		log.Println("Invalid handshake message from", h.addr)
	}
	return nil
}

// Process handshake message on the client side.
// This function is intended to be called on client's side.
// If this is the final handshake message, then new Peer object
// will be created and used as a transport. If no mutually
// authenticated Peer is ready, then return nil.
func (h *Handshake) Client(data []byte) *Peer {
	// ENC(H(DSAPub), R+1, El(SDHPub)) + ENC(K, R, RS + SS) + IDtag
	if h.rServer == nil && h.key == nil &&
		((!h.Conf.Encless && len(data) >= 80) ||
			(h.Conf.Encless && len(data) == 2*(EnclessEnlargeSize+h.Conf.MTU))) {
		// Decrypt remote public key
		sDHRepr := new([32]byte)
		var tmp []byte
		var err error
		if h.Conf.Encless {
			tmp, err = EnclessDecode(
				h.dsaPubH,
				h.rNonceNext(1),
				data[:len(data)/2],
			)
			if err != nil {
				log.Println("Unable to decode packet from", h.addr, err)
				return nil
			}
			copy(sDHRepr[:], tmp[:32])
		} else {
			salsa20.XORKeyStream(
				sDHRepr[:],
				data[:32],
				h.rNonceNext(1),
				h.dsaPubH,
			)
		}

		// Compute shared key
		sDH := new([32]byte)
		extra25519.RepresentativeToPublicKey(sDH, sDHRepr)
		h.key = dhKeyGen(h.dhPriv, sDH)

		// Decrypt Rs
		h.rServer = new([RSize]byte)
		h.sServer = new([SSize]byte)
		if h.Conf.Encless {
			tmp, err = EnclessDecode(
				h.key,
				h.rNonce[:],
				data[len(data)/2:len(data)-xtea.BlockSize],
			)
			if err != nil {
				log.Println("Unable to decode packet from", h.addr, err)
				return nil
			}
			copy(h.rServer[:], tmp[:RSize])
			copy(h.sServer[:], tmp[RSize:RSize+SSize])
		} else {
			decRs := make([]byte, RSize+SSize)
			salsa20.XORKeyStream(
				decRs,
				data[SSize:SSize+RSize+SSize],
				h.rNonce[:],
				h.key,
			)
			copy(h.rServer[:], decRs[:RSize])
			copy(h.sServer[:], decRs[RSize:])
		}

		// Generate R* and signature and encrypt them
		h.rClient = new([RSize]byte)
		if _, err = Rand.Read(h.rClient[:]); err != nil {
			log.Fatalln("Error reading random for R:", err)
		}
		h.sClient = new([SSize]byte)
		if _, err = Rand.Read(h.sClient[:]); err != nil {
			log.Fatalln("Error reading random for S:", err)
		}
		sign := ed25519.Sign(h.Conf.DSAPriv, h.key[:])

		var enc []byte
		if h.Conf.Noise {
			enc = make([]byte, h.Conf.MTU-xtea.BlockSize)
		} else {
			enc = make([]byte, RSize+RSize+SSize+ed25519.SignatureSize)
		}
		copy(enc, h.rServer[:])
		copy(enc[RSize:], h.rClient[:])
		copy(enc[RSize+RSize:], h.sClient[:])
		copy(enc[RSize+RSize+SSize:], sign[:])
		if h.Conf.Encless {
			enc, err = EnclessEncode(h.key, h.rNonceNext(1), enc)
			if err != nil {
				panic(err)
			}
		} else {
			salsa20.XORKeyStream(enc, enc, h.rNonceNext(1), h.key)
		}

		// Send that to server
		h.conn.Write(append(enc, idTag(h.Conf.Id, h.Conf.TimeSync, enc)...))
		h.LastPing = time.Now()
	} else
	// ENC(K, R+2, RC) + IDtag
	if h.key != nil && ((!h.Conf.Encless && len(data) >= 16) ||
		(h.Conf.Encless && len(data) == EnclessEnlargeSize+h.Conf.MTU)) {
		var err error
		// Decrypt rClient
		var dec []byte
		if h.Conf.Encless {
			dec, err = EnclessDecode(
				h.key,
				h.rNonceNext(2),
				data[:len(data)-xtea.BlockSize],
			)
			if err != nil {
				log.Println("Unable to decode packet from", h.addr, err)
				return nil
			}
			dec = dec[:RSize]
		} else {
			dec = make([]byte, RSize)
			salsa20.XORKeyStream(dec, data[:RSize], h.rNonceNext(2), h.key)
		}
		if subtle.ConstantTimeCompare(dec, h.rClient[:]) != 1 {
			log.Println("Invalid client's random number with", h.addr)
			return nil
		}

		// Switch peer
		peer := newPeer(
			true,
			h.addr,
			h.conn,
			h.Conf,
			keyFromSecrets(h.sServer[:], h.sClient[:]),
		)
		h.LastPing = time.Now()
		return peer
	} else {
		log.Println("Invalid handshake stage from", h.addr)
	}
	return nil
}
