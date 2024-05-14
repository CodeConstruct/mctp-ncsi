`mctp-ncsi`: NC-SI over MCTP implementation
===========================================

`mctp-nsci` is a small utility to implement NC-SI (and Ethernet) over MCTP, as
specified by [DMTF DSP0261][1], on top of the Linux kernel's MCTP socket
support.

This is implemented by creating a Linux "tap" network device. Packets sent
through this device will be encapsulated as MCTP messages and sent to a MCTP
endpoint, specified by EID (and optional network ID, for multi-net setups).

Usage
-----

```
mctp-ncsi [--ethernet] [--name IFNAME] <addr>
```

Where:
 * `addr` is a MCTP address in the form `eid` or `net,eid`. The `eid` can
   either be specified in decimal or hex (requiring a leading `0x`).
 * `IFNAME` is an optional interface name to request

If the `--ethernet` argument is given, `mctp-ncsi` will also implement the
Ethernet-over-MCTP protocol.

If `--name IFNAME` is given, this will be used as the tap device name, otherwise
a default of `tapN` will be allocated by the kernel.

Once the process is running, you'll want to bring the device up:

```sh
mctp-ncsi --name ncsi0 10 &
ip link set ncsi0 up
```

Limitations
-----------

This code is only a prototype at this stage! Test coverage is manual and not
comprehensive.

Only one interface is supported currently. Because of the nature of sockets,
only one process can bind() to the required MCTP types, so we can't run
multiple interfaces over separate processes.

[1]: https://www.dmtf.org/dsp/DSP0261
