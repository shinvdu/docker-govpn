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

package main

import (
	"bytes"
	"log"
	"net"
	"time"

	"cypherpunks.ru/govpn"
)

func startTCP() {
	bind, err := net.ResolveTCPAddr("tcp", *bindAddr)
	if err != nil {
		log.Fatalln("Can not resolve bind address:", err)
	}
	listener, err := net.ListenTCP("tcp", bind)
	if err != nil {
		log.Fatalln("Can not listen on TCP:", err)
	}
	log.Println("Listening on TCP:" + *bindAddr)
	go func() {
		for {
			conn, err := listener.AcceptTCP()
			if err != nil {
				log.Println("Error accepting TCP:", err)
				continue
			}
			go handleTCP(conn)
		}
	}()
}

func handleTCP(conn net.Conn) {
	addr := conn.RemoteAddr().String()
	buf := make([]byte, govpn.EnclessEnlargeSize+2*govpn.MTUMax)
	var n int
	var err error
	var prev int
	var hs *govpn.Handshake
	var ps *PeerState
	var peer *govpn.Peer
	var tap *govpn.TAP
	var conf *govpn.PeerConf
	for {
		if prev == len(buf) {
			break
		}
		conn.SetReadDeadline(time.Now().Add(time.Duration(govpn.TimeoutDefault) * time.Second))
		n, err = conn.Read(buf[prev:])
		if err != nil {
			// Either EOFed or timeouted
			break
		}
		prev += n
		peerId := idsCache.Find(buf[:prev])
		if peerId == nil {
			continue
		}
		if hs == nil {
			conf = confs[*peerId]
			if conf == nil {
				log.Println("Can not get peer configuration:", peerId.String())
				break
			}
			hs = govpn.NewHandshake(addr, conn, conf)
		}
		peer = hs.Server(buf[:prev])
		prev = 0
		if peer == nil {
			continue
		}
		hs.Zero()
		log.Println("Peer handshake finished:", addr, peer.Id.String())
		peersByIdLock.RLock()
		addrPrev, exists := peersById[*peer.Id]
		peersByIdLock.RUnlock()
		if exists {
			peersLock.Lock()
			peers[addrPrev].terminator <- struct{}{}
			tap = peers[addrPrev].tap
			ps = &PeerState{
				peer:       peer,
				tap:        tap,
				terminator: make(chan struct{}),
			}
			go peerReady(*ps)
			peersByIdLock.Lock()
			kpLock.Lock()
			delete(peers, addrPrev)
			delete(knownPeers, addrPrev)
			peers[addr] = ps
			knownPeers[addr] = &peer
			peersById[*peer.Id] = addr
			peersLock.Unlock()
			peersByIdLock.Unlock()
			kpLock.Unlock()
			log.Println("Rehandshake processed:", peer.Id.String())
		} else {
			ifaceName, err := callUp(peer.Id, peer.Addr)
			if err != nil {
				peer = nil
				break
			}
			tap, err = govpn.TAPListen(ifaceName, peer.MTU)
			if err != nil {
				log.Println("Unable to create TAP:", err)
				peer = nil
				break
			}
			ps = &PeerState{
				peer:       peer,
				tap:        tap,
				terminator: make(chan struct{}, 1),
			}
			go peerReady(*ps)
			peersLock.Lock()
			peersByIdLock.Lock()
			kpLock.Lock()
			peers[addr] = ps
			peersById[*peer.Id] = addr
			knownPeers[addr] = &peer
			peersLock.Unlock()
			peersByIdLock.Unlock()
			kpLock.Unlock()
			log.Println("Peer created:", peer.Id.String())
		}
		break
	}
	if hs != nil {
		hs.Zero()
	}
	if peer == nil {
		return
	}

	nonceExpectation := make([]byte, govpn.NonceSize)
	peer.NonceExpectation(nonceExpectation)
	prev = 0
	var i int
	for {
		if prev == len(buf) {
			break
		}
		conn.SetReadDeadline(time.Now().Add(conf.Timeout))
		n, err = conn.Read(buf[prev:])
		if err != nil {
			// Either EOFed or timeouted
			break
		}
		prev += n
	CheckMore:
		if prev < govpn.MinPktLength {
			continue
		}
		i = bytes.Index(buf[:prev], nonceExpectation)
		if i == -1 {
			continue
		}
		if !peer.PktProcess(buf[:i+govpn.NonceSize], tap, false) {
			log.Println(
				"Unauthenticated packet, dropping connection",
				addr, peer.Id.String(),
			)
			break
		}
		peer.NonceExpectation(nonceExpectation)
		copy(buf, buf[i+govpn.NonceSize:prev])
		prev = prev - i - govpn.NonceSize
		goto CheckMore
	}
	peer.Zero()
}
