#!/usr/bin/env bash

set -exuo pipefail

base_domain=switcheroo.markasoftware.com
listen_port=3553

# start the server and be sure to kill it when we're done
trap 'kill $(jobs -p)' EXIT
python3 dns_switcheroo.py --base-domain "$base_domain" --listen-host 127.0.0.1 --listen-port "$listen_port" --ip 1.1.1.1 --ip 8.8.8.8 --ip 192.168.0.1 &
sleep 1 # give it time to start up

# @param $1 the subdomain to query under the base domain
# @param $2 the source IP
big_dig() {
    local subdomain="$1"
    local source_ip="$2"
    dig @127.0.0.1 -b "$2" -p "$listen_port" -q "$subdomain.$base_domain" -t A +short +timeout=1
}

# @param $1 the message to fail with
fail_msg() {
    set +x
    echo
    echo "ASSERTION FAILED: $1"
    exit 1
}

[[ $(big_dig foo 127.0.0.1) == 1.1.1.1 ]] || fail_msg "Wrong first result"
[[ $(big_dig foo 127.0.0.1) == 1.1.1.1 ]] || fail_msg "Second request from same IP was not the same"
[[ $(big_dig foo 127.0.0.2) == 8.8.8.8 ]] || fail_msg "Request from second IP was not right"
[[ $(big_dig foo 127.0.0.1) == 1.1.1.1 ]] || fail_msg "Request from first IP for the third time was not the same"
[[ $(big_dig foo 127.0.0.88) == 192.168.0.1 ]] || fail_msg "Request from third IP was not right"
[[ $(big_dig foo 127.0.0.127) == 192.168.0.1 ]] || fail_msg "Request from fourth IP was not right"
[[ $(big_dig foo 127.0.0.2) == 8.8.8.8 ]] || fail_msg "Request from second IP again was not right"
[[ $(big_dig foo 127.0.0.88) == 192.168.0.1 ]] || fail_msg "Request from third IP again was not right"

[[ $(big_dig bar 127.0.0.2) == 1.1.1.1 ]] || fail_msg "Wrong first result on second subdomain using second IP from first subdomain"

[[ $(big_dig foo 127.0.0.2) == 8.8.8.8 ]] || fail_msg "Wrong result using second IP on first subdomain for the last time"

[[ $(big_dig FoO 127.0.0.2) == 8.8.8.8 ]] || fail_msg "Wrong result with inconsistent subdomain casing"
# there's actually a bit of a different code path if the first one has uppercasing, so let's test that
[[ $(big_dig HACK 127.0.0.1) == 1.1.1.1 ]] || fail_msg "wtf, we already tested this"
[[ $(big_dig HACK 127.0.0.2) == 8.8.8.8 ]] || fail_msg "Wrong result on second req when first had inconsistent subdomain casing"

base_domain="${base_domain//a/A}"
[[ $(big_dig foo 127.0.0.2) == 8.8.8.8 ]] || fail_msg "Wrong result with inconsistent base domain casing"

set +x
echo
echo All tests passed!
