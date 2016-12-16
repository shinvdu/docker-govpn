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

// Verifier generator and validator for GoVPN VPN daemon.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"

	"cypherpunks.ru/govpn"
)

var (
	keyPath  = flag.String("key", "", "Path to passphrase file")
	verifier = flag.String("verifier", "", "Optional verifier")
	mOpt     = flag.Int("m", govpn.DefaultM, "Argon2d memory parameter (KiBs)")
	tOpt     = flag.Int("t", govpn.DefaultT, "Argon2d iteration parameter")
	pOpt     = flag.Int("p", govpn.DefaultP, "Argon2d parallelizm parameter")
	egdPath  = flag.String("egd", "", "Optional path to EGD socket")
	warranty = flag.Bool("warranty", false, "Print warranty information")
)

func main() {
	flag.Parse()
	if *warranty {
		fmt.Println(govpn.Warranty)
		return
	}
	if *egdPath != "" {
		govpn.EGDInit(*egdPath)
	}
	key, err := govpn.KeyRead(*keyPath)
	if err != nil {
		log.Fatalln("Unable to read the key", err)
	}
	if *verifier == "" {
		id := new([govpn.IDSize]byte)
		if _, err := govpn.Rand.Read(id[:]); err != nil {
			log.Fatalln(err)
		}
		pid := govpn.PeerId(*id)
		v := govpn.VerifierNew(*mOpt, *tOpt, *pOpt, &pid)
		v.PasswordApply(key)
		fmt.Println(v.LongForm())
		fmt.Println(v.ShortForm())
		return
	}
	v, err := govpn.VerifierFromString(*verifier)
	if err != nil {
		log.Fatalln("Can not decode verifier", err)
	}
	if v.Pub == nil {
		log.Fatalln("Verifier does not contain public key")
	}
	pub := *v.Pub
	v.PasswordApply(key)
	fmt.Println(bytes.Equal(v.Pub[:], pub[:]))
}
