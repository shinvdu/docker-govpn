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
	"bufio"
	"encoding/base64"
	"log"
	"net"
	"net/http"
)

func proxyTCP(timeouted, rehandshaking, termination chan struct{}) {
	proxyAddr, err := net.ResolveTCPAddr("tcp", *proxyAddr)
	if err != nil {
		log.Fatalln("Can not resolve proxy address:", err)
	}
	conn, err := net.DialTCP("tcp", nil, proxyAddr)
	if err != nil {
		log.Fatalln("Can not connect to proxy:", err)
	}
	req := "CONNECT " + *remoteAddr + " HTTP/1.1\n"
	req += "Host: " + *remoteAddr + "\n"
	if *proxyAuth != "" {
		req += "Proxy-Authorization: Basic "
		req += base64.StdEncoding.EncodeToString([]byte(*proxyAuth)) + "\n"
	}
	req += "\n"
	conn.Write([]byte(req))
	resp, err := http.ReadResponse(
		bufio.NewReader(conn),
		&http.Request{Method: "CONNECT"},
	)
	if err != nil || resp.StatusCode != http.StatusOK {
		log.Fatalln("Unexpected response from proxy")
	}
	log.Println("Connected to proxy:", *proxyAddr)
	go handleTCP(conn, timeouted, rehandshaking, termination)
}
