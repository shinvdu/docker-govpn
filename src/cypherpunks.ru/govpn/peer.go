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
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/poly1305"
	"golang.org/x/crypto/salsa20"
	"golang.org/x/crypto/xtea"
)

const (
	NonceSize       = 8
	NonceBucketSize = 128
	TagSize         = poly1305.TagSize
	// S20BS is Salsa20's internal blocksize in bytes
	S20BS = 64
	// Maximal amount of bytes transfered with single key (4 GiB)
	MaxBytesPerKey uint64 = 1 << 32
	// Heartbeat rate, relative to Timeout
	TimeoutHeartbeat = 4
	// Minimal valid packet length
	MinPktLength = 1 + 16 + 8
	// Padding byte
	PadByte = byte(0x80)
)

func newNonceCipher(key *[32]byte) *xtea.Cipher {
	nonceKey := make([]byte, 16)
	salsa20.XORKeyStream(
		nonceKey,
		make([]byte, 32),
		make([]byte, xtea.BlockSize),
		key,
	)
	ciph, err := xtea.NewCipher(nonceKey)
	if err != nil {
		panic(err)
	}
	return ciph
}

type Peer struct {
	// Statistics (they are at the beginning for correct int64 alignment)
	BytesIn         uint64
	BytesOut        uint64
	BytesPayloadIn  uint64
	BytesPayloadOut uint64
	FramesIn        uint64
	FramesOut       uint64
	FramesUnauth    uint64
	FramesDup       uint64
	HeartbeatRecv   uint64
	HeartbeatSent   uint64

	// Basic
	Addr string
	Id   *PeerId
	Conn io.Writer `json:"-"`

	// Traffic behaviour
	NoiseEnable bool
	CPR         int
	CPRCycle    time.Duration `json:"-"`
	Encless     bool
	MTU         int

	// Cryptography related
	Key          *[SSize]byte `json:"-"`
	NonceCipher  *xtea.Cipher `json:"-"`
	nonceRecv    uint64
	nonceLatest  uint64
	nonceOur     uint64
	NonceExpect  uint64 `json:"-"`
	nonceBucket0 map[uint64]struct{}
	nonceBucket1 map[uint64]struct{}
	nonceFound0  bool
	nonceFound1  bool
	nonceBucketN int32

	// Timers
	Timeout       time.Duration `json:"-"`
	Established   time.Time
	LastPing      time.Time
	LastSent      time.Time
	willSentCycle time.Time

	// Receiver
	BusyR    sync.Mutex `json:"-"`
	bufR     []byte
	tagR     *[TagSize]byte
	keyAuthR *[SSize]byte
	pktSizeR int

	// Transmitter
	BusyT    sync.Mutex `json:"-"`
	bufT     []byte
	tagT     *[TagSize]byte
	keyAuthT *[SSize]byte
	frameT   []byte
	now      time.Time
}

func (p *Peer) String() string {
	return p.Id.String() + ":" + p.Addr
}

// Zero peer's memory state.
func (p *Peer) Zero() {
	p.BusyT.Lock()
	p.BusyR.Lock()
	SliceZero(p.Key[:])
	SliceZero(p.bufR)
	SliceZero(p.bufT)
	SliceZero(p.keyAuthR[:])
	SliceZero(p.keyAuthT[:])
	p.BusyT.Unlock()
	p.BusyR.Unlock()
}

func (p *Peer) NonceExpectation(buf []byte) {
	binary.BigEndian.PutUint64(buf, p.NonceExpect)
	p.NonceCipher.Encrypt(buf, buf)
}

func cprCycleCalculate(conf *PeerConf) time.Duration {
	if conf.CPR == 0 {
		return time.Duration(0)
	}
	rate := conf.CPR * 1 << 10
	if conf.Encless {
		rate /= EnclessEnlargeSize + conf.MTU
	} else {
		rate /= conf.MTU
	}
	return time.Second / time.Duration(rate)
}

func newPeer(isClient bool, addr string, conn io.Writer, conf *PeerConf, key *[SSize]byte) *Peer {
	now := time.Now()
	timeout := conf.Timeout

	cprCycle := cprCycleCalculate(conf)
	noiseEnable := conf.Noise
	if conf.CPR > 0 {
		noiseEnable = true
		timeout = cprCycle
	} else {
		timeout = timeout / TimeoutHeartbeat
	}

	bufSize := S20BS + 2*conf.MTU
	if conf.Encless {
		bufSize += EnclessEnlargeSize
		noiseEnable = true
	}
	peer := Peer{
		Addr: addr,
		Id:   conf.Id,
		Conn: conn,

		NoiseEnable: noiseEnable,
		CPR:         conf.CPR,
		CPRCycle:    cprCycle,
		Encless:     conf.Encless,
		MTU:         conf.MTU,

		Key:          key,
		NonceCipher:  newNonceCipher(key),
		nonceBucket0: make(map[uint64]struct{}, NonceBucketSize),
		nonceBucket1: make(map[uint64]struct{}, NonceBucketSize),

		Timeout:     timeout,
		Established: now,
		LastPing:    now,

		bufR:     make([]byte, bufSize),
		bufT:     make([]byte, bufSize),
		tagR:     new([TagSize]byte),
		tagT:     new([TagSize]byte),
		keyAuthR: new([SSize]byte),
		keyAuthT: new([SSize]byte),
	}
	if isClient {
		peer.nonceOur = 1
		peer.NonceExpect = 0 + 2
	} else {
		peer.nonceOur = 0
		peer.NonceExpect = 1 + 2
	}
	return &peer

}

// Process incoming Ethernet packet.
// ready channel is TAPListen's synchronization channel used to tell him
// that he is free to receive new packets. Encrypted and authenticated
// packets will be sent to remote Peer side immediately.
func (p *Peer) EthProcess(data []byte) {
	if len(data) > p.MTU-1 { // 1 is for padding byte
		log.Println("Padded data packet size", len(data)+1, "is bigger than MTU", p.MTU, p)
		return
	}
	p.now = time.Now()
	p.BusyT.Lock()

	// Zero size is a heartbeat packet
	SliceZero(p.bufT)
	if len(data) == 0 {
		// If this heartbeat is necessary
		if !p.LastSent.Add(p.Timeout).Before(p.now) {
			p.BusyT.Unlock()
			return
		}
		p.bufT[S20BS+0] = PadByte
		p.HeartbeatSent++
	} else {
		// Copy payload to our internal buffer and we are ready to
		// accept the next one
		copy(p.bufT[S20BS:], data)
		p.bufT[S20BS+len(data)] = PadByte
		p.BytesPayloadOut += uint64(len(data))
	}

	if p.NoiseEnable && !p.Encless {
		p.frameT = p.bufT[S20BS : S20BS+p.MTU-TagSize]
	} else if p.Encless {
		p.frameT = p.bufT[S20BS : S20BS+p.MTU]
	} else {
		p.frameT = p.bufT[S20BS : S20BS+len(data)+1+NonceSize]
	}
	p.nonceOur += 2
	binary.BigEndian.PutUint64(p.frameT[len(p.frameT)-NonceSize:], p.nonceOur)
	p.NonceCipher.Encrypt(
		p.frameT[len(p.frameT)-NonceSize:],
		p.frameT[len(p.frameT)-NonceSize:],
	)
	var out []byte
	if p.Encless {
		var err error
		out, err = EnclessEncode(
			p.Key,
			p.frameT[len(p.frameT)-NonceSize:],
			p.frameT[:len(p.frameT)-NonceSize],
		)
		if err != nil {
			panic(err)
		}
		out = append(out, p.frameT[len(p.frameT)-NonceSize:]...)
	} else {
		salsa20.XORKeyStream(
			p.bufT[:S20BS+len(p.frameT)-NonceSize],
			p.bufT[:S20BS+len(p.frameT)-NonceSize],
			p.frameT[len(p.frameT)-NonceSize:],
			p.Key,
		)
		copy(p.keyAuthT[:], p.bufT[:SSize])
		poly1305.Sum(p.tagT, p.frameT, p.keyAuthT)
		atomic.AddUint64(&p.BytesOut, uint64(len(p.frameT)+TagSize))
		out = append(p.tagT[:], p.frameT...)
	}
	p.FramesOut++

	if p.CPRCycle != time.Duration(0) {
		p.willSentCycle = p.LastSent.Add(p.CPRCycle)
		if p.willSentCycle.After(p.now) {
			time.Sleep(p.willSentCycle.Sub(p.now))
			p.now = p.willSentCycle
		}
	}

	p.LastSent = p.now
	p.Conn.Write(out)
	p.BusyT.Unlock()
}

func (p *Peer) PktProcess(data []byte, tap io.Writer, reorderable bool) bool {
	if len(data) < MinPktLength {
		return false
	}
	if !p.Encless && len(data) > len(p.bufR)-S20BS {
		return false
	}
	var out []byte
	p.BusyR.Lock()
	if p.Encless {
		var err error
		out, err = EnclessDecode(
			p.Key,
			data[len(data)-NonceSize:],
			data[:len(data)-NonceSize],
		)
		if err != nil {
			p.FramesUnauth++
			p.BusyR.Unlock()
			return false
		}
	} else {
		for i := 0; i < SSize; i++ {
			p.bufR[i] = 0
		}
		copy(p.bufR[S20BS:], data[TagSize:])
		salsa20.XORKeyStream(
			p.bufR[:S20BS+len(data)-TagSize-NonceSize],
			p.bufR[:S20BS+len(data)-TagSize-NonceSize],
			data[len(data)-NonceSize:],
			p.Key,
		)
		copy(p.keyAuthR[:], p.bufR[:SSize])
		copy(p.tagR[:], data[:TagSize])
		if !poly1305.Verify(p.tagR, data[TagSize:], p.keyAuthR) {
			p.FramesUnauth++
			p.BusyR.Unlock()
			return false
		}
		out = p.bufR[S20BS : S20BS+len(data)-TagSize-NonceSize]
	}

	// Check if received nonce is known to us in either of two buckets.
	// If yes, then this is ignored duplicate.
	// Check from the oldest bucket, as in most cases this will result
	// in constant time check.
	// If Bucket0 is filled, then it becomes Bucket1.
	p.NonceCipher.Decrypt(
		data[len(data)-NonceSize:],
		data[len(data)-NonceSize:],
	)
	p.nonceRecv = binary.BigEndian.Uint64(data[len(data)-NonceSize:])
	if reorderable {
		_, p.nonceFound0 = p.nonceBucket0[p.nonceRecv]
		_, p.nonceFound1 = p.nonceBucket1[p.nonceRecv]
		if p.nonceFound0 || p.nonceFound1 || p.nonceRecv+2*NonceBucketSize < p.nonceLatest {
			p.FramesDup++
			p.BusyR.Unlock()
			return false
		}
		p.nonceBucket0[p.nonceRecv] = struct{}{}
		p.nonceBucketN++
		if p.nonceBucketN == NonceBucketSize {
			p.nonceBucket1 = p.nonceBucket0
			p.nonceBucket0 = make(map[uint64]struct{}, NonceBucketSize)
			p.nonceBucketN = 0
		}
	} else {
		if p.nonceRecv != p.NonceExpect {
			p.FramesDup++
			p.BusyR.Unlock()
			return false
		}
		p.NonceExpect += 2
	}
	if p.nonceRecv > p.nonceLatest {
		p.nonceLatest = p.nonceRecv
	}

	p.FramesIn++
	atomic.AddUint64(&p.BytesIn, uint64(len(data)))
	p.LastPing = time.Now()
	p.pktSizeR = bytes.LastIndexByte(out, PadByte)
	if p.pktSizeR == -1 {
		p.BusyR.Unlock()
		return false
	}
	// Validate the pad
	for i := p.pktSizeR + 1; i < len(out); i++ {
		if out[i] != 0 {
			p.BusyR.Unlock()
			return false
		}
	}

	if p.pktSizeR == 0 {
		p.HeartbeatRecv++
		p.BusyR.Unlock()
		return true
	}
	p.BytesPayloadIn += uint64(p.pktSizeR)
	tap.Write(out[:p.pktSizeR])
	p.BusyR.Unlock()
	return true
}
