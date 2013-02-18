# ip-header

IP header parsing.

[![Build Status](https://travis-ci.org/wanderview/node-ip-header.png)](https://travis-ci.org/wanderview/node-ip-header)

## Example

```javascript
var IpHeader = require('ip-header');

var iph = new IpHeader(buf);
iph.src === '1.1.1.1';            // source IP address
iph.dst === '2.2.2.2';            // destination IP address
iph.flags.df === true;            // don't fragment flag
iph.flags.mf === false;           // more fragments flag
iph.id === 12345;                 // IP identifier for frag reassembly
iph.offset === 0;                 // fragment offset
iph.ttl === 64;                   // time-to-live
iph.protocol === 'tcp';           // payload protocol
iph.protocolCode === 6;           // code for the payload protocol
iph.bytes === 20;                 // length of IP header in bytes
iph.totalBytes === 520;           // total length of IP packet in bytes
var data = buf.slice(iph.bytes, iph.totalBytes);
```
