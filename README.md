# ip-header

IP header parsing.

[![Build Status](https://travis-ci.org/wanderview/node-ip-header.png)](https://travis-ci.org/wanderview/node-ip-header)

## Example

```javascript
var IpHeader = require('ip-header');

// parse an IP header from buffer
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
iph.length === 20;                // length of IP header in bytes
iph.totalLength === 520;          // total length of IP packet in bytes
iph.dataLength === 500;           // size of data payload (total - header)
var data = buf.slice(iph.length, iph.totalLength);

// create a new IP header from scratch
var iph2 = new IpHeader({
  src: '1.1.1.1',
  dst: '3.3.3.3',
  protocol: 'udp',
  dataLength: 58
});
var out = iph2.toBuffer();         // write header out to new buffer

// operate on buffers in place
var iph3 = new IpHeader(buf, offset);
var iph4 = IpHeader.fromBuffer(buf, offset);
iph3.toBuffer(buf, offset);
```

## Limitations

* Only supports IPv4.  Buffer parsing throws if an IPv6 header is seen.
* Only supports common protocols as readable strings.  Throws if other
  protocols are seen.  If you need another protocol, send a pull request
  to add it.
  * `'icmp'` - 1
  * `'igmp'` - 2
  * `'tcp'` - 6
  * `'udp'` - 17
  * `'encap'` - 41
  * `'ospf'` - 89
  * `'sctp'` - 132
* Does not support options.  Throws if the IP header length is not exactly
  20 bytes.
