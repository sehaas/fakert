# FakeRT

Fake your trace routes.

`fakert` creates a TUN device and adjusts your routing table to handle all incoming traffic for the configured network.

UDP and ICMP traceroute requests are correctly handled, so most clients should be happy with response.

It's tested with an IPv6 network. For IPv4 some modification would be required, but who owns a public IPv4 network anyway.
Due to the [netlink](https://github.com/vishvananda/netlink) package, only Linux is supported.

## Usage

`fakert [-iface <name>] [-config <filename>]`

```
2020/06/21 17:59:30 FakeRT Tun
2020/06/21 17:59:30 config: Network 2001:db8::/64
2020/06/21 17:59:30 config: Route 2001:db8::c0:ffee
2020/06/21 17:59:30 config:      Hop 0 2001:db8::aaaa
2020/06/21 17:59:30 config:      Hop 1 2001:db8::bbbb
2020/06/21 17:59:30 config:      Hop 2 2001:db8::cccc
2020/06/21 17:59:30 config:      Hop 3 2001:db8::c0:ffee
2020/06/21 17:59:30 Found device fakert0 tuntap
2020/06/21 17:59:30 dest: ff02::16 | src: fe80::8b44:848d:d23b:518e | TTL: 1 | type: 0
2020/06/21 17:59:30 dest: ff02::16 | src: fe80::8b44:848d:d23b:518e | TTL: 1 | type: 0
2020/06/21 17:59:31 dest: ff02::16 | src: fe80::8b44:848d:d23b:518e | TTL: 1 | type: 0
2020/06/21 17:59:31 dest: ff02::16 | src: fe80::8b44:848d:d23b:518e | TTL: 1 | type: 0
```

## Config
The tool reads the config from `fakert.yml`.
The property `network` is required to bring up the routing.
If no routes are configured, `fakert` will directly answer with the requested IP address.

```yaml
network:
    2001:db8::/64

routes:
    2001:db8::c0:ffee:
    - 2001:db8::aaaa
    - 2001:db8::bbbb
    - 2001:db8::cccc
    - 2001:db8::c0:ffee
```

## License & Credit

The code is licensed under the MIT License and based on [traceroute-haiku](https://github.com/benjojo/traceroute-haiku).
