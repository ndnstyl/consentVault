import test from "node:test";
import assert from "node:assert/strict";
import { isPublicAddress } from "../src/egress.ts";

// Every IPv6 form that embeds an IPv4 address or names a non-global range is refused; ordinary global unicast is not.
const refused = [
  "::7f00:1", "::127.0.0.1", "::a00:1", "::ffff:7f00:1", "::ffff:127.0.0.1", "::ffff:0:7f00:1", "::ffff:0:127.0.0.1",
  "0:0:0:0:0:ffff:7f00:1", "2002::", "2002:7f00:1::", "2002:5db8:d822::1", "fec0::1", "feff::1", "fe80::1", "fc00::1",
  "fd12:3456::1", "2001::1", "2001:0:4136:e378::1", "64:ff9b::7f00:1", "64:ff9b:1::1", "2001:db8::1", "100::1", "::", "::1",
  "ff02::1", "2001:10::1", "2001:20::1", "[::7f00:1]",
];
const allowed = ["2606:4700:4700::1111", "2a00:1450:4001:80b::200e", "2001:4860:4860::8888", "93.184.216.34"];

for (const a of refused) test(`refuses ${a}`, () => assert.equal(isPublicAddress(a), false, a));
for (const a of allowed) test(`allows ${a}`, () => assert.equal(isPublicAddress(a), true, a));
