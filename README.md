# Arbitrary IP DNS

DNS server that resolves subdomains to arbitrary IPs. Eg, `192.168.0.1.ip.markasoftware.com` -> `192.168.0.1`

This is useful for pentesting in cases when a reserved IP like 192.168.0.1 might be blocked, but domain names that resolve to 192.168.0.1 aren't blocked.

Sometimes a simple blocker might just look for a banned IP as a substring, you can also write the IPs in english: `one-nine-two.one-six-eight.zero.one.ip.markasoftware.com` for example to bypass this.

It's a simple Python 3 script with no dependencies outside the Python stdlib.

Run the included python script with `-h` to learn how to use it.
