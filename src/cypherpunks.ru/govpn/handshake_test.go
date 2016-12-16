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
	"testing"
)

func TestHandshakeSymmetric(t *testing.T) {
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerId)
	testConf.Verifier = v
	testConf.DSAPriv = v.PasswordApply("does not matter")
	hsS := NewHandshake("server", Dummy{&testCt}, testConf)
	hsC := HandshakeStart("client", Dummy{&testCt}, testConf)
	hsS.Server(testCt)
	hsC.Client(testCt)
	if hsS.Server(testCt) == nil {
		t.Fail()
	}
	if hsC.Client(testCt) == nil {
		t.Fail()
	}
}

func TestHandshakeNoiseSymmetric(t *testing.T) {
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerId)
	testConf.Verifier = v
	testConf.DSAPriv = v.PasswordApply("does not matter")
	testConf.Noise = true
	hsS := NewHandshake("server", Dummy{&testCt}, testConf)
	hsC := HandshakeStart("client", Dummy{&testCt}, testConf)
	hsS.Server(testCt)
	hsC.Client(testCt)
	if hsS.Server(testCt) == nil {
		t.Fail()
	}
	if hsC.Client(testCt) == nil {
		t.Fail()
	}
	testConf.Noise = false
}
func TestHandshakeEnclessSymmetric(t *testing.T) {
	// initial values are taken from peer_test.go's init()
	v := VerifierNew(1<<10, 1<<4, 1, &testPeerId)
	testConf.Verifier = v
	testConf.DSAPriv = v.PasswordApply("does not matter")
	testConf.Encless = true
	testConf.Noise = true
	hsS := NewHandshake("server", Dummy{&testCt}, testConf)
	hsC := HandshakeStart("client", Dummy{&testCt}, testConf)
	hsS.Server(testCt)
	hsC.Client(testCt)
	if hsS.Server(testCt) == nil {
		t.Fail()
	}
	if hsC.Client(testCt) == nil {
		t.Fail()
	}
	testConf.Encless = false
	testConf.Noise = false
}
