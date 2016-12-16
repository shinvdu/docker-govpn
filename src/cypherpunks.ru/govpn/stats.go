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
	"encoding/json"
	"log"
	"net"
	"time"
)

const (
	RWTimeout = 10 * time.Second
)

type KnownPeers map[string]**Peer

// StatsProcessor is assumed to be run in background. It accepts
// connection on statsPort, reads anything one send to them and show
// information about known peers in serialized JSON format. peers
// argument is a reference to the map with references to the peers as
// values. Map is used here because of ease of adding and removing
// elements in it.
func StatsProcessor(statsPort net.Listener, peers *KnownPeers) {
	var conn net.Conn
	var err error
	var data []byte
	buf := make([]byte, 2<<8)
	for {
		conn, err = statsPort.Accept()
		if err != nil {
			log.Println("Error during accepting connection", err.Error())
			continue
		}
		conn.SetDeadline(time.Now().Add(RWTimeout))
		conn.Read(buf)
		conn.Write([]byte("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n"))
		var peersList []*Peer
		for _, peer := range *peers {
			peersList = append(peersList, *peer)
		}
		data, err = json.Marshal(peersList)
		if err != nil {
			panic(err)
		}
		conn.Write(data)
		conn.Close()
	}
}
