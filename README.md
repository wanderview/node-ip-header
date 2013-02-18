# ip-header

IP header parsing.

[![Build Status](https://travis-ci.org/wanderview/node-ip-header.png)](https://travis-ci.org/wanderview/node-ip-header)

## Example

```javascript
var IpHeader = require('ip-header');

var iph = new IpHeader(buf);
iph.src === '1.1.1.1';            // true
iph.dst === '2.2.2.2';            // true
var data = buf.slice(iph.bytes);
```
