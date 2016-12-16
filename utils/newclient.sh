#!/bin/sh -e

PATH=$PATH:.

[ -n "$1" ] || {
    cat <<EOF
Example script for creating new user peer for GoVPN.
It asks for passphrase, generates verifier and shows you example
YAML entry for server configuration.

Usage: $0 <username>
EOF
    exit 1
}

username=$1
verifier=$(govpn-verifier)
verifierS=$(echo $verifier | sed 's/^\(.*\) .*$/\1/')
verifierC=$(echo $verifier | sed 's/^.* \(.*\)$/\1/')
echo

cat <<EOF
Your client verifier is: $verifierC

Place the following YAML configuration entry on the server's side:

    $username:
        up: /path/to/up.sh
        iface: or TAP interface name
        verifier: $verifierS
EOF
