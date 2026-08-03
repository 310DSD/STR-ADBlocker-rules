# Third-party notices

The compiled `rules/rules.bin` is built from HaGeZi DNS Blocklists, copyright
HaGeZi and contributors, licensed under GPL-3.0. The unmodified source and license
are available at:

- https://github.com/hagezi/dns-blocklists
- https://github.com/hagezi/dns-blocklists/blob/main/LICENSE

STR AdBlocker extracts canonical domains, applies the allowlist, sorts and
deduplicates them, and stores them in its mmap rule format. The ruleset manifest
records the source URLs, build timestamp, count, and binary digest.

The optional coverage command reads d3ward's d3Host list from its upstream location
at test time. It does not redistribute that list. The upstream declares it under
CC BY-NC-SA:

- https://github.com/d3ward/toolz/blob/master/src/d3host.txt

The FlowGuard native capability probe uses `github.com/cilium/ebpf`, copyright
the Cilium eBPF authors, under the MIT License:

- https://github.com/cilium/ebpf
- https://github.com/cilium/ebpf/blob/main/LICENSE

The native binaries use `golang.org/x/sys`, copyright the Go authors, under the
BSD 3-Clause License:

- https://pkg.go.dev/golang.org/x/sys
- https://cs.opensource.google/go/x/sys/+/master:LICENSE

The FlowGuard clsact compatibility adapter uses `github.com/vishvananda/netlink`
and its `github.com/vishvananda/netns` dependency, copyright their contributors,
under the Apache License 2.0:

- https://github.com/vishvananda/netlink
- https://github.com/vishvananda/netlink/blob/main/LICENSE
- https://github.com/vishvananda/netns
- https://github.com/vishvananda/netns/blob/main/LICENSE
