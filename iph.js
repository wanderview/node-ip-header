// Copyright (c) 2013, Benjamin J. Kelly ("Author")
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice, this
//    list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
// ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
// WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
// DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
// ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
// (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
// LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
// ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

'use strict';

module.exports = IpHeader;

var ip = require('ip');

// most common protocols, expand as needed
var PROTOCOL_TO_STRING = {
  1: 'icmp',
  2: 'igmp',
  6: 'tcp',
  17: 'udp',
  41: 'encap',
  89: 'ospf',
  132: 'sctp'
};

var PROTOCOL_FROM_STRING = {
  icmp: 1,
  igmp: 2,
  tcp: 6,
  udp: 17,
  encap: 41,
  ospf: 89,
  sctp: 132
};

function IpHeader(opts, offset) {
  if (opts instanceof Buffer) {
    return IpHeader.fromBuffer(opts, offset);
  }

  var self = (this instanceof IpHeader)
           ? this
           : Object.create(IpHeader.prototype);

  opts = opts || {};

  self.flags = {};
  self.flags.df = opts.flags && opts.flags.df;
  self.flags.mf = opts.flags && opts.flags.mf;
  self.id = ~~opts.id;
  self.offset = ~~opts.offset;
  self.ttl = opts.ttl || 64;
  self.src = opts.src || '127.0.0.1';
  self.dst = opts.dst || '127.0.0.1';
  self.length = opts.length || 20;

  if (self.length !== 20) {
    throw new Error('Unsupported IP header length [' + self.length +
                    ']; must be 20 since options are not implemented.');
  }

  if (opts.dataLength) {
    self.dataLength = opts.dataLength;
    self.totalLength = self.length + self.dataLength;
  } else {
    self.totalLength = opts.totalLength || self.length;
    self.dataLength = self.totalLength - self.length;
  }

  if (opts.protocol) {
    self.protocol = opts.protocol;
    self.protocolCode = PROTOCOL_FROM_STRING[self.protocol];
  } else if (opts.protocolCode) {
    self.protocolCode = opts.protocolCode;
    self.protocol = PROTOCOL_TO_STRING[self.protocolCode];
  } else {
    self.protocol = 'tcp';
    self.protocolCode = PROTOCOL_FROM_STRING[self.protocol];
  }

  if (!self.protocolCode) {
    throw new Error('Unsupported protocol [' + self.protocol + ']');
  }

  return self;
}

IpHeader.fromBuffer = function(buf, offset) {
  offset = ~~offset;

  var tmp = buf.readUInt8(offset);
  offset += 1;

  var version = (tmp & 0xf0) >> 4;
  if (version != 4) {
    throw new Error('Unsupported IP version [' + version + ']; must be IPv4.');
  }

  var headerLength = (tmp & 0x0f) * 4;

  // skip DSCP and ECN fields
  offset += 1;

  var totalLength = buf.readUInt16BE(offset);
  offset += 2;

  var id = buf.readUInt16BE(offset);
  offset += 2;

  tmp = buf.readUInt16BE(offset);
  offset += 2;

  var flags = (tmp & 0xe000) >> 13;
  var fragmentOffset = tmp & 0x1fff;

  var df = !!(flags & 0x2);
  var mf = !!(flags & 0x4);

  var ttl = buf.readUInt8(offset);
  offset += 1;

  var protocolCode = buf.readUInt8(offset);
  offset += 1;

  var protocol = PROTOCOL_TO_STRING[protocolCode];
  if (!protocol) {
    throw new Error('Unsupported protocol code [' + protocolCode + ']');
  }

  var checksum = buf.readUInt16BE(offset);
  offset += 2;

  var src = ip.toString(buf.slice(offset, offset + 4));
  offset += 4;

  var dst = ip.toString(buf.slice(offset, offset + 4));
  offset += 4;

  // TODO: read options

  return new IpHeader({
    flags: { df: df, mf: mf },
    id: id,
    offset: fragmentOffset,
    ttl: ttl,
    protocol: protocol,
    protocolCode: protocolCode,
    src: src,
    dst: dst,
    length: headerLength,
    totalLength: totalLength
  });
};

IpHeader.prototype.toBuffer = function(buf, offset) {
  offset = ~~offset;
  buf = (buf instanceof Buffer) ? buf : new Buffer(offset + this.length);

  var startOffset = offset;

  var tmp = 0x40 | ((this.length / 4) & 0x0f);
  buf.writeUInt8(tmp, offset);
  offset += 1;

  // skip DSCP and ECN fields
  buf.writeUInt8(0, offset);
  offset += 1;

  buf.writeUInt16BE(this.totalLength, offset);
  offset += 2;

  buf.writeUInt16BE(this.id, offset);
  offset += 2;

  var dfMask = this.flags.df ? 0x2 : 0;
  var mfMask = this.flags.mf ? 0x4 : 0;
  var flags = dfMask | mfMask;
  tmp = (flags << 13) | (this.offset & 0x1fff)

  buf.writeUInt16BE(tmp, offset);
  offset += 2;

  buf.writeUInt8(this.ttl, offset);
  offset += 1;

  buf.writeUInt8(this.protocolCode, offset);
  offset += 1;

  // write zero checksum for now
  var checksumOffset = offset;
  buf.writeUInt16BE(0, offset);
  offset += 2;

  ip.toBuffer(this.src).copy(buf, offset);
  offset += 4;

  ip.toBuffer(this.dst).copy(buf, offset);
  offset += 4;

  // recalculate the checksum
  var sum = 0;
  for (var i = startOffset; i < offset; i += 2) {
    sum += buf.readUInt16BE(i);
  }
  var carry = (sum & 0x0f0000) >> 16;
  var checksum = (~(sum + carry)) & 0xffff;
  buf.writeUInt16BE(checksum, checksumOffset);

  // TODO: write options

  return buf;
};
