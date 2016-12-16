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
	"time"

	"github.com/agl/ed25519"
)

type PeerConf struct {
	Id          *PeerId       `yaml:"-"`
	Name        string        `yaml:"name"`
	Iface       string        `yaml:"iface"`
	MTU         int           `yaml:"mtu"`
	Up          string        `yaml:"up"`
	Down        string        `yaml:"down"`
	TimeoutInt  int           `yaml:"timeout"`
	Timeout     time.Duration `yaml:"-"`
	Noise       bool          `yaml:"noise"`
	CPR         int           `yaml:"cpr"`
	Encless     bool          `yaml:"encless"`
	TimeSync    int           `yaml:"timesync"`
	VerifierRaw string        `yaml:"verifier"`

	// This is passphrase verifier
	Verifier *Verifier `yaml:"-"`
	// This field exists only on client's side
	DSAPriv *[ed25519.PrivateKeySize]byte `yaml:"-"`
}
