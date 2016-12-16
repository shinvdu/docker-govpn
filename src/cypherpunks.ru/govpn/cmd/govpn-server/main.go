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

// Simple secure, DPI/censorship-resistant free software VPN daemon.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"time"

	"cypherpunks.ru/govpn"
)

var (
	bindAddr = flag.String("bind", "[::]:1194", "Bind to address")
	proto    = flag.String("proto", "udp", "Protocol to use: udp, tcp or all")
	confPath = flag.String("conf", "peers.yaml", "Path to configuration YAML")
	stats    = flag.String("stats", "", "Enable stats retrieving on host:port")
	proxy    = flag.String("proxy", "", "Enable HTTP proxy on host:port")
	egdPath  = flag.String("egd", "", "Optional path to EGD socket")
	warranty = flag.Bool("warranty", false, "Print warranty information")
)

func main() {
	flag.Parse()
	if *warranty {
		fmt.Println(govpn.Warranty)
		return
	}
	timeout := time.Second * time.Duration(govpn.TimeoutDefault)
	log.SetFlags(log.Ldate | log.Lmicroseconds | log.Lshortfile)
	log.Println(govpn.VersionGet())

	confInit()
	knownPeers = govpn.KnownPeers(make(map[string]**govpn.Peer))

	if *egdPath != "" {
		log.Println("Using", *egdPath, "EGD")
		govpn.EGDInit(*egdPath)
	}

	switch *proto {
	case "udp":
		startUDP()
	case "tcp":
		startTCP()
	case "all":
		startUDP()
		startTCP()
	default:
		log.Fatalln("Unknown protocol specified")
	}

	termSignal := make(chan os.Signal, 1)
	signal.Notify(termSignal, os.Interrupt, os.Kill)

	hsHeartbeat := time.Tick(timeout)
	go func() { <-hsHeartbeat }()

	if *stats != "" {
		log.Println("Stats are going to listen on", *stats)
		statsPort, err := net.Listen("tcp", *stats)
		if err != nil {
			log.Fatalln("Can not listen on stats port:", err)
		}
		go govpn.StatsProcessor(statsPort, &knownPeers)
	}
	if *proxy != "" {
		go proxyStart()
	}
	log.Println("Server started")

	var needsDeletion bool
MainCycle:
	for {
		select {
		case <-termSignal:
			log.Println("Terminating")
			for _, ps := range peers {
				govpn.ScriptCall(
					confs[*ps.peer.Id].Down,
					ps.tap.Name,
					ps.peer.Addr,
				)
			}
			break MainCycle
		case <-hsHeartbeat:
			now := time.Now()
			hsLock.Lock()
			for addr, hs := range handshakes {
				if hs.LastPing.Add(timeout).Before(now) {
					log.Println("Deleting handshake state", addr)
					hs.Zero()
					delete(handshakes, addr)
				}
			}
			peersLock.Lock()
			peersByIdLock.Lock()
			kpLock.Lock()
			for addr, ps := range peers {
				ps.peer.BusyR.Lock()
				needsDeletion = ps.peer.LastPing.Add(timeout).Before(now)
				ps.peer.BusyR.Unlock()
				if needsDeletion {
					log.Println("Deleting peer", ps.peer)
					delete(peers, addr)
					delete(knownPeers, addr)
					delete(peersById, *ps.peer.Id)
					go govpn.ScriptCall(
						confs[*ps.peer.Id].Down,
						ps.tap.Name,
						ps.peer.Addr,
					)
					ps.terminator <- struct{}{}
				}
			}
			hsLock.Unlock()
			peersLock.Unlock()
			peersByIdLock.Unlock()
			kpLock.Unlock()
		}
	}
}
