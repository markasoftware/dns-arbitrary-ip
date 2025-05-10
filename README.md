# Pentesting DNS servers

Currently contains two different dns servers:
+ `dns_arbitrary_ip.py`: Resolves subdomains to arbitrary IPs, eg `192.168.0.1.ip.markasoftware.com`
  -> `192.168.0.1`. This is useful in cases when a service attempts to block IP addresses, but not
  domains that resolve to said IPs.

  A simple blocker might just look for a banned IP as a substring, so you can also write the IPs in
  English: `one-nine-two.one-six-eight.zero.one.ip.markasoftware.com` -> `192.168.0.1`
+ `dns_switcheroo.py`: Resolves to different IPs for each subsequent DNS lookup. More specifically,
  the first DNS lookup will return the first IP specified with the `--ip` cli option, and the source
  IP that made that request will be saved so all future DNS lookups from that source IP return the
  same IP. The second DNS lookup will return the second IP specified with `--ip`, and that source IP
  will be saved too, etc. This behavior continues until all `--ip` options have been exhausted, then
  the final `--ip` is returned for all subsequent lookups.

  This behaivor is isolated per subdomain, so eg if `--base-domain=example.com` then
  `foo.example.com` will resolve to the first IP, then the second, etc, while `bar.example.com` is
  completely unaffected and will still start on the first IP if it's resolved later.

Both are simple Python scripts with no dependencies outside the stdlib (though you do have to clone
the whole repo so `lib_dns.py` is accessible). Command line usage is documented with `--help`. Happy
hacking!
