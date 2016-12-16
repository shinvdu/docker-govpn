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
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/agl/ed25519"
	"github.com/magical/argon2"
	"golang.org/x/crypto/ssh/terminal"
)

const (
	DefaultM = 1 << 12
	DefaultT = 1 << 7
	DefaultP = 1
)

type Verifier struct {
	M   int
	T   int
	P   int
	Id  *PeerId
	Pub *[ed25519.PublicKeySize]byte
}

// Generate new verifier for given peer, with specified password and
// hashing parameters.
func VerifierNew(m, t, p int, id *PeerId) *Verifier {
	return &Verifier{M: m, T: t, P: p, Id: id}
}

// Apply the password: create Ed25519 keypair based on it, save public
// key in verifier.
func (v *Verifier) PasswordApply(password string) *[ed25519.PrivateKeySize]byte {
	r, err := argon2.Key([]byte(password), v.Id[:], v.T, v.P, int64(v.M), 32)
	if err != nil {
		log.Fatalln("Unable to apply Argon2d", err)
	}
	defer SliceZero(r)
	src := bytes.NewBuffer(r)
	pub, prv, err := ed25519.GenerateKey(src)
	if err != nil {
		log.Fatalln("Unable to generate Ed25519 keypair", err)
	}
	v.Pub = pub
	return prv
}

// Parse either short or long verifier form.
func VerifierFromString(input string) (*Verifier, error) {
	s := strings.Split(input, "$")
	if len(s) < 4 || s[1] != "argon2d" {
		return nil, errors.New("Invalid verifier structure")
	}
	var m, t, p int
	n, err := fmt.Sscanf(s[2], "m=%d,t=%d,p=%d", &m, &t, &p)
	if n != 3 || err != nil {
		return nil, errors.New("Invalid verifier parameters")
	}
	salt, err := base64.RawStdEncoding.DecodeString(s[3])
	if err != nil {
		return nil, err
	}
	v := Verifier{M: m, T: t, P: p}
	id := new([IDSize]byte)
	copy(id[:], salt)
	pid := PeerId(*id)
	v.Id = &pid
	if len(s) == 5 {
		pub, err := base64.RawStdEncoding.DecodeString(s[4])
		if err != nil {
			return nil, err
		}
		v.Pub = new([ed25519.PublicKeySize]byte)
		copy(v.Pub[:], pub)
	}
	return &v, nil
}

// Short verifier string form -- it is useful for the client.
// Does not include public key.
func (v *Verifier) ShortForm() string {
	return fmt.Sprintf(
		"$argon2d$m=%d,t=%d,p=%d$%s",
		v.M, v.T, v.P, base64.RawStdEncoding.EncodeToString(v.Id[:]),
	)
}

// Long verifier string form -- it is useful for the server.
// Includes public key.
func (v *Verifier) LongForm() string {
	return fmt.Sprintf(
		"%s$%s", v.ShortForm(),
		base64.RawStdEncoding.EncodeToString(v.Pub[:]),
	)
}

// Read the key either from text file (if path is specified), or
// from the terminal.
func KeyRead(path string) (string, error) {
	var p []byte
	var err error
	var pass string
	if path == "" {
		os.Stderr.Write([]byte("Passphrase:"))
		p, err = terminal.ReadPassword(0)
		os.Stderr.Write([]byte("\n"))
		pass = string(p)
	} else {
		p, err = ioutil.ReadFile(path)
		pass = strings.TrimRight(string(p), "\n")
	}
	if err != nil {
		return "", err
	}
	if len(pass) == 0 {
		return "", errors.New("Empty passphrase submitted")
	}
	return pass, err
}
