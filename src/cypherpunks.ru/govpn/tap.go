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
	"io"
)

type TAP struct {
	Name string
	Sink chan []byte
	dev  io.ReadWriter
}

var (
	taps = make(map[string]*TAP)
)

func NewTAP(ifaceName string, mtu int) (*TAP, error) {
	tapRaw, err := newTAPer(ifaceName)
	if err != nil {
		return nil, err
	}
	tap := TAP{
		Name: ifaceName,
		dev:  tapRaw,
		Sink: make(chan []byte),
	}
	go func() {
		var n int
		var err error
		var buf []byte
		buf0 := make([]byte, mtu)
		buf1 := make([]byte, mtu)
		bufZ := false
		for {
			if bufZ {
				buf = buf0
			} else {
				buf = buf1
			}
			bufZ = !bufZ
			n, err = tap.dev.Read(buf)
			if err != nil {
				panic("Reading TAP:" + err.Error())
			}
			tap.Sink <- buf[:n]
		}
	}()
	return &tap, nil
}

func (t *TAP) Write(data []byte) (n int, err error) {
	return t.dev.Write(data)
}

func TAPListen(ifaceName string, mtu int) (*TAP, error) {
	tap, exists := taps[ifaceName]
	if exists {
		return tap, nil
	}
	tap, err := NewTAP(ifaceName, mtu)
	if err != nil {
		return nil, err
	}
	taps[ifaceName] = tap
	return tap, nil
}
