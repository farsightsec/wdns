[![Build Status](https://travis-ci.org/farsightsec/wdns.png?branch=master)](https://travis-ci.org/farsightsec/wdns)

Farsight wdns
=============

`wdns` is a low-level C library for dealing with wire-format dns packets.

Contact information
-------------------

Questions about `wdns`, should be directed to the `wdns-dev` mailing list:

https://lists.farsightsecurity.com/mailman/listinfo/wdns-dev

Building and installing wdns
----------------------------

wdns has the following external dependencies:

* [pcap](http://www.tcpdump.org/)

* [pkg-config](https://wiki.freedesktop.org/www/Software/pkg-config/)

On Debian systems, the following packages should be installed, if available:

    pkg-config libpcap0.8-dev

Note that on Debian systems, binary packages of wdns are available from
[a Debian package repository maintained by Farsight Security](https://archive.farsightsecurity.com/SIE_Software_Installation_Debian/).
These packages should be used in preference to building from source on
Debian-based systems.

On FreeBSD systems, the following ports should be installed, if available:

    devel/pkgconf

After satisfying the prerequisites, `./configure && make && make install` should
compile and install `libwdns` `/usr/local`. If building from a git checkout,
run the `./autogen.sh` command first to generate the `configure` script.

Examples
--------

C language examples are in the `examples/` directory.
