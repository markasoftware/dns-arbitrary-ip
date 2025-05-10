#!/usr/bin/env bash

set -exuo pipefail

base_domain=ip.markasoftware.com
listen_port=3553

# start the server and be sure to kill it when we're done
trap 'kill $(jobs -p)' EXIT
./dns_arbitrary_ip.py --base-domain "$base_domain" --listen-host 127.0.0.1 --listen-port "$listen_port" &
sleep 1 # give it time to start up

# @param $1 the hostname to query, under the 
big_dig() {
    local subdomain="$1"
    dig @127.0.0.1 -p "$listen_port" -q "$subdomain.$base_domain" -t A +short +timeout=1
}

# @param $1 the message to fail with
fail_msg() {
    echo "ASSERTION FAILED: $1"
    exit 1
}

[[ $(big_dig 192.168.0.1) == 192.168.0.1 ]] || fail_msg "Couldn't do basic numeric query"
[[ $(big_dig one-nine-two.168.zero.one) == 192.168.0.1 ]] || fail_msg "Couldn't do mixed english-number query"

set +x
echo
echo All tests passed!
