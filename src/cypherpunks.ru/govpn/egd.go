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
	"crypto/rand"
	"errors"
	"io"
	"net"
)

var (
	Rand io.Reader = rand.Reader
)

type EGDRand string

// Read n bytes from EGD, blocking mode.
func (egdPath EGDRand) Read(b []byte) (int, error) {
	conn, err := net.Dial("unix", string(egdPath))
	if err != nil {
		return 0, err
	}
	conn.Write([]byte{0x02, byte(len(b))})
	read, err := conn.Read(b)
	if err != nil {
		conn.Close()
		return read, err
	}
	if read != len(b) {
		conn.Close()
		return read, errors.New("Got less bytes than expected from EGD")
	}
	conn.Close()
	return read, nil
}

func EGDInit(path string) {
	Rand = EGDRand(path)
}
