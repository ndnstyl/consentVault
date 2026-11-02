import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { amrFromExchange, ssoFromExchange, assertionConfigError, MisconfiguredError, signAssertion, whoFromExchange } from "../src/assertion.ts";
import { jwt, NOW_MS, nowSec } from "./support/portal.ts";

const pair = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
const PRIVATE_JWK = JSON.stringify({ ...pair.privateKey.export({ format: "jwk" }), kid: "edge1" });
const b64 = (s: string) => JSON.parse(Buffer.from(s, "base64url").toString("utf8"));

test("the sign-in method decides alone: a passkey counts; a password, a magic link, an OAuth sign-in or anything else does not", () => {
  assert.deepEqual(amrFromExchange({ authentication_method: "Passkey" }), ["hwk", "user"]);
  for (const m of ["Password", "MagicAuth", "GoogleOAuth", "MicrosoftOAuth", "passkey", "Passkey ", "", 7, null, undefined]) {
    assert.deepEqual(amrFromExchange({ authentication_method: m as never }), [], String(m));
  }
  assert.deepEqual(amrFromExchange({ authentication_method: "Password", authentication_factors: [{ id: "f" }] } as never), [], "a factor list is not read");
  assert.deepEqual(amrFromExchange({}), []);
});

test("company single sign-on counts only when the provider names the connection and its organization; a personal Google or Microsoft account never does", () => {
  const conn = "conn_01E4ZCR3C56J083X43JQXF3JK5", org = "org_01E4ZCR3C56J083X43JQXF3JK5";
  assert.deepEqual(amrFromExchange({ authentication_method: "SSO", sso_connection_id: conn, organization_id: org } as never), ["sso"]);
  for (const bad of [{ authentication_method: "SSO" }, { authentication_method: "SSO", sso_connection_id: conn },
    { authentication_method: "SSO", organization_id: org }, { authentication_method: "SSO", sso_connection_id: "x", organization_id: org },
    { authentication_method: "SSO", sso_connection_id: conn, organization_id: "x" }, { authentication_method: "SSO", sso_connection_id: 5, organization_id: org },
    { authentication_method: "GoogleOAuth", sso_connection_id: conn, organization_id: org }, { authentication_method: "Password", sso_connection_id: conn, organization_id: org }]) {
    assert.deepEqual(amrFromExchange(bad as never), [], JSON.stringify(bad));
  }
  assert.deepEqual(ssoFromExchange({ authentication_method: "SSO", sso_connection_id: conn, organization_id: org } as never), { connection: conn, organization: org });
  assert.equal(ssoFromExchange({ authentication_method: "Passkey", sso_connection_id: conn, organization_id: org } as never), null, "only an SSO sign-in carries one");
});

test("the signed assertion names the connection and its organization for an SSO sign-in and only then", async () => {
  const sso = { connection: "conn_01E4ZCR3C56J083X43JQXF3JK5", organization: "org_01E4ZCR3C56J083X43JQXF3JK5" };
  const a = b64((await signAssertion({ ASSERTION_KEY_JWK: PRIVATE_JWK }, "t", "u", ["sso"], "SSO", NOW_MS, undefined, sso)).split(".")[1]);
  assert.equal(a.sso_connection_id, sso.connection);
  assert.equal(a.sso_organization_id, sso.organization);
  assert.deepEqual(a.amr, ["sso"]);
  const p = b64((await signAssertion({ ASSERTION_KEY_JWK: PRIVATE_JWK }, "t", "u", ["hwk", "user"], "Passkey", NOW_MS)).split(".")[1]);
  assert.equal("sso_connection_id" in p || "sso_organization_id" in p, false);
});

test("the verified address comes from the provider's answer; a missing or odd one is no address", () => {
  assert.deepEqual(whoFromExchange({ user: { email: "a@b.example", email_verified: true } }), { email: "a@b.example", email_verified: true });
  assert.deepEqual(whoFromExchange({ user: { email: "a@b.example" } }), { email: "a@b.example", email_verified: false });
  assert.deepEqual(whoFromExchange({ user: { email: "a@b.example", email_verified: "true" } }), { email: "a@b.example", email_verified: false });
  for (const bad of [{}, { user: {} }, { user: { email: 5 } }, { user: { email: "" } }]) assert.deepEqual(whoFromExchange(bad), { email: null, email_verified: false });
});

test("the assertion is a short ES256 statement for this person and this exact token, in the shape the vault checks", async () => {
  const token = jwt({ sub: "user_1", exp: nowSec() + 300 });
  const a = (await signAssertion({ ASSERTION_KEY_JWK: PRIVATE_JWK }, token, "user_1", ["hwk", "user"], "Passkey", NOW_MS))!;
  const [h, p, s] = a.split(".");
  assert.deepEqual(b64(h), { alg: "ES256", typ: "JWT", kid: "edge1" });
  const c = b64(p);
  assert.equal(c.iss, "consentvault-portal-edge");
  assert.equal(c.aud, "consentvault-vault");
  assert.equal(c.sub, "user_1");
  assert.equal(c.tok, crypto.createHash("sha256").update(token).digest("hex"));
  assert.deepEqual(c.amr, ["hwk", "user"]);
  assert.equal(c.method, "Passkey");
  assert.equal(c.iat, nowSec());
  assert.equal(c.exp - c.iat, 60);
  assert.ok(crypto.verify("sha256", Buffer.from(`${h}.${p}`), { key: pair.publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url")), "verifies under the edge's public key");
  assert.ok(!crypto.verify("sha256", Buffer.from(`${h}.${p}x`), { key: pair.publicKey, dsaEncoding: "ieee-p1363" }, Buffer.from(s, "base64url")));
});

test("a missing, broken or incomplete signing key is a named deployment fault, never a quiet 'no second factor'", async () => {
  for (const env of [{}, { ASSERTION_KEY_JWK: "not json" }, { ASSERTION_KEY_JWK: JSON.stringify({ kty: "EC" }) }]) {
    assert.match(assertionConfigError(env)!, /ASSERTION_KEY_JWK/);
    await assert.rejects(() => signAssertion(env, "t", "u", ["mfa"], "x", NOW_MS), MisconfiguredError);
  }
  assert.equal(assertionConfigError({ ASSERTION_KEY_JWK: PRIVATE_JWK }), null);
});

test("the assertion carries the provider-verified address when there is one", async () => {
  const a = await signAssertion({ ASSERTION_KEY_JWK: PRIVATE_JWK }, "t", "u", ["hwk", "user"], "Passkey", NOW_MS, { email: "d@acme.example", email_verified: true });
  assert.equal(b64(a.split(".")[1]).email, "d@acme.example");
  assert.equal(b64(a.split(".")[1]).email_verified, true);
  assert.equal("email" in b64((await signAssertion({ ASSERTION_KEY_JWK: PRIVATE_JWK }, "t", "u", [], "Password", NOW_MS)).split(".")[1]), false);
});
