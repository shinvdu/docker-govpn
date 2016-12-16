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
	"log"
	"os"
	"os/exec"
	"runtime"
)

const (
	TimeoutDefault = 60
	EtherSize      = 14
	MTUMax         = 9000 + EtherSize + 1
	MTUDefault     = 1500 + EtherSize + 1

	ENV_IFACE  = "GOVPN_IFACE"
	ENV_REMOTE = "GOVPN_REMOTE"
)

var (
	Version string
)

// Call external program/script.
// You have to specify path to it and (inteface name as a rule) something
// that will be the first argument when calling it. Function will return
// it's output and possible error.
func ScriptCall(path, ifaceName, remoteAddr string) ([]byte, error) {
	if path == "" {
		return nil, nil
	}
	if _, err := os.Stat(path); err != nil && os.IsNotExist(err) {
		return nil, err
	}
	cmd := exec.Command(path)
	cmd.Env = append(cmd.Env, ENV_IFACE+"="+ifaceName)
	cmd.Env = append(cmd.Env, ENV_REMOTE+"="+remoteAddr)
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Println("Script error", path, err, string(out))
	}
	return out, err
}

// Zero each byte.
func SliceZero(data []byte) {
	for i := 0; i < len(data); i++ {
		data[i] = 0
	}
}

func VersionGet() string {
	return "GoVPN version " + Version + " built with " + runtime.Version()
}
