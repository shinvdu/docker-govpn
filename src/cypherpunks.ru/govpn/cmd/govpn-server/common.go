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
	"sync"
	"time"

	"cypherpunks.ru/govpn"
)

type PeerState struct {
	peer       *govpn.Peer
	terminator chan struct{}
	tap        *govpn.TAP
}

var (
	handshakes map[string]*govpn.Handshake = make(map[string]*govpn.Handshake)
	hsLock     sync.RWMutex

	peers     map[string]*PeerState = make(map[string]*PeerState)
	peersLock sync.RWMutex

	peersById     map[govpn.PeerId]string = make(map[govpn.PeerId]string)
	peersByIdLock sync.RWMutex

	knownPeers govpn.KnownPeers
	kpLock     sync.RWMutex
)

func peerReady(ps PeerState) {
	var data []byte
	heartbeat := time.NewTicker(ps.peer.Timeout)
Processor:
	for {
		select {
		case <-heartbeat.C:
			ps.peer.EthProcess(nil)
		case <-ps.terminator:
			break Processor
		case data = <-ps.tap.Sink:
			ps.peer.EthProcess(data)
		}
	}
	close(ps.terminator)
	ps.peer.Zero()
	heartbeat.Stop()
}

func callUp(peerId *govpn.PeerId, remoteAddr string) (string, error) {
	ifaceName := confs[*peerId].Iface
	if confs[*peerId].Up != "" {
		result, err := govpn.ScriptCall(confs[*peerId].Up, ifaceName, remoteAddr)
		if err != nil {
			log.Println("Script", confs[*peerId].Up, "call failed", err)
			return "", err
		}
		if ifaceName == "" {
			sepIndex := bytes.Index(result, []byte{'\n'})
			if sepIndex < 0 {
				sepIndex = len(result)
			}
			ifaceName = string(result[:sepIndex])
		}
	}
	if ifaceName == "" {
		log.Println("Can not obtain interface name for", *peerId)
	}
	return ifaceName, nil
}
