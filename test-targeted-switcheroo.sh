#!/usr/bin/env bash

set -exuo pipefail

base_domain=targeted-switcheroo.markasoftware.com
listen_port=3553
dnsmasq_port=5335

trap 'kill $(jobs -p) 2>/dev/null' EXIT
# using -k to keep in "foreground" so that it'll be in jobs
# this is a bit of an incantation, i had to play around with it a lot to get it to return SOA records for the reverse IP
dnsmasq -k -p "$dnsmasq_port" --auth-zone=my-tld. --auth-server supersekritstring.notexists --host-record=foo.my-tld,127.0.0.42 --auth-zone=42.0.0.127.in-addr.arpa &

# @param $1 the subdomain to query under the base domain
# @param $2 the IP to query from
big_dig() {
    local subdomain="$1"
    local source_ip="$2"
    dig @127.0.0.1 -b "$source_ip" -p "$listen_port" -q "$subdomain.$base_domain" -t A +short +timeout=1
}

# @param $1 the message to fail with
fail_msg() {
    set +x
    echo
    echo "ASSERTION FAILED: $1"
    exit 1
}

# @params all extra args to dns_targeted_switcheroo.py 
start_server() {
    ./dns_targeted_switcheroo.py --base-domain "$base_domain" --listen-host 127.0.0.1 --listen-port "$listen_port" --public-dns-server 127.0.0.1 --public-dns-server-port "$dnsmasq_port" "$@" &
    our_pid="$!"
    sleep 1
}

stop_server() {
    kill "$our_pid"
}

start_server --fallback-ip 5.6.7.8
[[ $(big_dig foo 127.0.0.1) == 5.6.7.8 ]] || fail_msg "Should use fallback IP when no matchers specified"
stop_server

start_server --ip-mapping notasubstring,9.9.9.9 --fallback-ip 5.6.7.8
[[ $(big_dig foo 127.0.0.1) == 5.6.7.8 ]] || fail_msg "Should use fallback IP when matchers do not match"
stop_server

start_server --ip-mapping sekrit,9.9.9.9 --fallback-ip 5.6.7.8
[[ $(big_dig foo 127.0.0.42) == 9.9.9.9 ]] || fail_msg "Should match when matched in SOA MNAME"
[[ $(big_dig foo 127.0.0.1) == 5.6.7.8 ]] || fail_msg "Should use fallback IP when not on the sekrit domain"
stop_server

start_server --ip-mapping hostmaster,9.9.9.9 --fallback-ip 5.6.7.8
[[ $(big_dig foo 127.0.0.42) == 9.9.9.9 ]] || fail_msg "Should match when matched in SOA RNAME"
stop_server

start_server --ip-mapping foo.my-tld,9.9.9.9 --fallback-ip 5.6.7.8
[[ $(big_dig foo 127.0.0.42) == 9.9.9.9 ]] || fail_msg "Should match when matched in PTR"
stop_server

start_server --ip-mapping notachance,8.8.8.8 --ip-mapping foo.my-tld,78.87.78.87 --ip-mapping hostmaster,10.0.0.1 --ip-mapping sekrit,9.9.9.9 --ip-mapping nope,1.2.3.4 --fallback-ip 5.6.7.8
[[ $(big_dig foo 127.0.0.42) == 78.87.78.87 ]] || fail_msg "Many matchers, precedence"
[[ $(big_dig foo 127.0.0.1) == 5.6.7.8 ]] || fail_msg "Many matchers, all failed"
stop_server

set +x
echo
echo All tests passed!
