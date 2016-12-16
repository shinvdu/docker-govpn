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
	"sync/atomic"
	"time"

	"cypherpunks.ru/govpn"
)

func startTCP(timeouted, rehandshaking, termination chan struct{}) {
	remote, err := net.ResolveTCPAddr("tcp", *remoteAddr)
	if err != nil {
		log.Fatalln("Can not resolve remote address:", err)
	}
	conn, err := net.DialTCP("tcp", nil, remote)
	if err != nil {
		log.Fatalln("Can not connect to address:", err)
	}
	log.Println("Connected to TCP:" + *remoteAddr)
	handleTCP(conn, timeouted, rehandshaking, termination)
}

func handleTCP(conn *net.TCPConn, timeouted, rehandshaking, termination chan struct{}) {
	hs := govpn.HandshakeStart(*remoteAddr, conn, conf)
	buf := make([]byte, 2*(govpn.EnclessEnlargeSize+*mtu)+*mtu)
	var n int
	var err error
	var prev int
	var peer *govpn.Peer
	var terminator chan struct{}
HandshakeCycle:
	for {
		select {
		case <-termination:
			break HandshakeCycle
		default:
		}
		if prev == len(buf) {
			log.Println("Timeouted waiting for the packet")
			timeouted <- struct{}{}
			break HandshakeCycle
		}

		conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		n, err = conn.Read(buf[prev:])
		if err != nil {
			log.Println("Connection timeouted")
			timeouted <- struct{}{}
			break HandshakeCycle
		}

		prev += n
		peerId := idsCache.Find(buf[:prev])
		if peerId == nil {
			continue
		}
		peer = hs.Client(buf[:prev])
		prev = 0
		if peer == nil {
			continue
		}
		log.Println("Handshake completed")
		knownPeers = govpn.KnownPeers(map[string]**govpn.Peer{*remoteAddr: &peer})
		if firstUpCall {
			go govpn.ScriptCall(*upPath, *ifaceName, *remoteAddr)
			firstUpCall = false
		}
		hs.Zero()
		terminator = make(chan struct{})
		go func() {
			heartbeat := time.NewTicker(peer.Timeout)
			var data []byte
		Processor:
			for {
				select {
				case <-heartbeat.C:
					peer.EthProcess(nil)
				case <-terminator:
					break Processor
				case data = <-tap.Sink:
					peer.EthProcess(data)
				}
			}
			heartbeat.Stop()
			peer.Zero()
		}()
		break HandshakeCycle
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
TransportCycle:
	for {
		select {
		case <-termination:
			break TransportCycle
		default:
		}
		if prev == len(buf) {
			log.Println("Timeouted waiting for the packet")
			timeouted <- struct{}{}
			break TransportCycle
		}
		conn.SetReadDeadline(time.Now().Add(time.Duration(timeout) * time.Second))
		n, err = conn.Read(buf[prev:])
		if err != nil {
			log.Println("Connection timeouted")
			timeouted <- struct{}{}
			break TransportCycle
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
			log.Println("Unauthenticated packet, dropping connection")
			timeouted <- struct{}{}
			break TransportCycle
		}
		if atomic.LoadUint64(&peer.BytesIn)+atomic.LoadUint64(&peer.BytesOut) > govpn.MaxBytesPerKey {
			log.Println("Need rehandshake")
			rehandshaking <- struct{}{}
			break TransportCycle
		}
		peer.NonceExpectation(nonceExpectation)
		copy(buf, buf[i+govpn.NonceSize:prev])
		prev = prev - i - govpn.NonceSize
		goto CheckMore
	}
	if terminator != nil {
		terminator <- struct{}{}
	}
	peer.Zero()
	conn.Close()
}
