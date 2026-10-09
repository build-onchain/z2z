// Selected public fixtures from zcash/zcash at immutable commit
// 0512e9eb00f97172346e0fac854625d59771e4f7; no signatures were generated here.
// Literal V1 signed fixtures and their source-known evaluation outcomes:
// tx_valid.json lines 14-16, blob 265ba5de66c665d7407b41b57d4eeb6a03bdbd44;
// tx_invalid.json lines 12-16 and 222-226, blob b99a72da9b9909393cd8c59c32181ce99594bd51.
// https://github.com/zcash/zcash/blob/0512e9eb00f97172346e0fac854625d59771e4f7/src/test/data/tx_valid.json#L14-L16
// https://github.com/zcash/zcash/blob/0512e9eb00f97172346e0fac854625d59771e4f7/src/test/data/tx_invalid.json#L12-L16
// https://github.com/zcash/zcash/blob/0512e9eb00f97172346e0fac854625d59771e4f7/src/test/data/tx_invalid.json#L222-L226
// These signed rows supply evaluation results, not independent expected digests.
// Original license: https://github.com/zcash/zcash/blob/0512e9eb00f97172346e0fac854625d59771e4f7/COPYING
//
// Copyright (c) 2016-2019 The Zcash developers
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2009-2019 Bitcoin Developers
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

pub(super) const V1_SIGNED: &str = "01000000010001000000000000000000000000000000000000000000000000000000000000000000006a473044022067288ea50aa799543a536ff9306f8e1cba05b9c6b10951175b924f96732555ed022026d7b5265f38d21541519e4a1e55044d5b9e17e15cdbaf29ae3792e99e883e7a012103ba8c8b86dea131c22ab967e6dd99bdae8eff7a1f75a2c35f1f944109e3fe5e22ffffffff010000000000000000015100000000";
pub(super) const V1_SCRIPT: &str = "76a9145b6462475454710f3c22f5fdf0b40704c92f25c388ad51";
// tx_valid.json lines 44-47: both actual signatures are source-known valid.
// https://github.com/zcash/zcash/blob/0512e9eb00f97172346e0fac854625d59771e4f7/src/test/data/tx_valid.json#L44-L47
pub(super) const V1_ALL_ACP_SIGNED: &str = "010000000200010000000000000000000000000000000000000000000000000000000000000000000049483045022100d180fd2eb9140aeb4210c9204d3f358766eb53842b2a9473db687fa24b12a3cc022079781799cd4f038b85135bbe49ec2b57f306b2bb17101b17f71f000fcab2b6fb01ffffffff0002000000000000000000000000000000000000000000000000000000000000000000004847304402205f7530653eea9b38699e476320ab135b74771e1c48b81a5d041e2ca84b9be7a802200ac8d1f40fb026674fe5a5edd3dea715c27baa9baca51ed45ea750ac9dc0a55e81ffffffff010100000000000000015100000000";
pub(super) const V1_ALL_ACP_SCRIPT: &str = "21035e7f0d4d0841bcd56c39337ed086b1a633ee770c1ffdd94ac552a95ac2ce0efcac";
