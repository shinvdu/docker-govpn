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
	"log"
	"net/http"
)

type proxyHandler struct{}

func (p proxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err != nil {
		log.Println("Hijacking failed:", err.Error())
		return
	}
	conn.Write([]byte("HTTP/1.0 200 OK\n\n"))
	go handleTCP(conn)
}

func proxyStart() {
	log.Println("HTTP proxy listening on:" + *proxy)
	s := &http.Server{
		Addr:    *proxy,
		Handler: proxyHandler{},
	}
	log.Println("HTTP proxy result:", s.ListenAndServe())
}
