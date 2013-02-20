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

var IpHeader = require('../iph');

var path = require('path');
var pcap = require('pcap-parser');

var FILE = path.join(__dirname, 'data', 'netbios-ns-b-query-winxp.pcap');

module.exports.fromBuffer = function(test) {
  test.expect(12);

  var parser = pcap.parse(FILE);
  parser.on('packetData', function(payload) {
    var iph = IpHeader.fromBuffer(payload, 14);
    test.equals('192.168.207.128', iph.src);
    test.equals('192.168.207.2', iph.dst);
    test.equals(23793, iph.id);
    test.equals(128, iph.ttl);
    test.equals('udp', iph.protocol);
    test.equals(17, iph.protocolCode);
    test.equals(0, iph.offset);
    test.equals(false, iph.flags.df);
    test.equals(false, iph.flags.mf);
    test.equals(20, iph.length);
    test.equals(78, iph.totalLength);
    test.equals(58, iph.dataLength);

    test.done();
  });
};

module.exports.fromBufferNew = function(test) {
  test.expect(12);

  var parser = pcap.parse(FILE);
  parser.on('packetData', function(payload) {
    var iph = new IpHeader(payload, 14);
    test.equals('192.168.207.128', iph.src);
    test.equals('192.168.207.2', iph.dst);
    test.equals(23793, iph.id);
    test.equals(128, iph.ttl);
    test.equals('udp', iph.protocol);
    test.equals(17, iph.protocolCode);
    test.equals(0, iph.offset);
    test.equals(false, iph.flags.df);
    test.equals(false, iph.flags.mf);
    test.equals(20, iph.length);
    test.equals(78, iph.totalLength);
    test.equals(58, iph.dataLength);

    test.done();
  });
};

module.exports.toBuffer = function(test) {
  test.expect(20);

  var parser = pcap.parse(FILE);
  parser.on('packetData', function(payload) {
    // skip ether frame
    var etherData = payload.slice(14);

    var iph = new IpHeader(etherData);
    var buf = iph.toBuffer();

    for (var i = 0; i < iph.length; ++i) {
      test.equals(etherData[i], buf[i], 'byte at index [' + i + ']');
    }

    test.done();
  });
};

module.exports.toBufferInPlace = function(test) {
  test.expect(34);

  var parser = pcap.parse(FILE);
  parser.on('packetData', function(payload) {
    // skip ether frame
    var etherData = payload.slice(14);

    var iph = new IpHeader(etherData);
    var buf = new Buffer(payload.length);
    for (var i = 0; i < 14; ++i) {
      buf[i] = payload[i];
    }
    iph.toBuffer(buf, 14);

    for (var i = 0; i < (iph.length + 14); ++i) {
      test.equals(payload[i], buf[i], 'byte at index [' + i + ']');
    }

    test.done();
  });
};
