ProxyDetect
===========

* Author: geoff.jones@cyberis.co.uk
* Copyright: Cyberis Limited 2013
* License: GPLv3 (See LICENSE)

A Perl script to detect the existence of transparent proxies, using three common methods:

1. Check to see whether an intercepting proxy does a DNS lookup on a fake host header*;
2. Check to see whether the HTTP (TRACE) request headers are modified between the client and server;
3. Check to see whether a TCP traceroute on port 25 returns a different path to port 80.


Dependencies
------------
Perl, and nothing much else:
```perl
use IO::Socket;
use Term::ANSIColor;
```
Issues
------
Kindly report all issues via https://github.com/cyberisltd/ProxyDetect/issues
