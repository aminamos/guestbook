// auth/session.js — tiny signed-cookie sessions for Cloudflare Workers.
// No KV, no dependencies. All secrets come from env (wrangler secret put).
// Cookies are HMAC-SHA256 signed with SESSION_SECRET so the client can't
// forge them. Keep payloads small (a DPoP JWK + PKCE verifier fits fine).

const enc = new TextEncoder();
const dec = new TextDecoder();

export function b64uEncode(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64uDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

async function hmacKey(secret) {
  return crypto.subtle.importKey(
    "raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]
  );
}

export async function signCookie(value, secret) {
  const key = await hmacKey(secret);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(value));
  return value + "." + b64uEncode(new Uint8Array(sig));
}

export async function verifyCookie(signed, secret) {
  const i = signed.lastIndexOf(".");
  if (i < 0) return null;
  const value = signed.slice(0, i);
  const key = await hmacKey(secret);
  const ok = await crypto.subtle.verify("HMAC", key, enc.encode(value), b64uDecode(signed.slice(i + 1)));
  return ok ? value : null;
}

export function getCookie(req, name) {
  const h = req.headers.get("cookie") || "";
  for (const part of h.split(";")) {
    const eq = part.indexOf("=");
    if (eq > 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

export async function setSignedCookie(headers, name, obj, secret, maxAgeSec) {
  const signed = await signCookie(b64uEncode(enc.encode(JSON.stringify(obj))), secret);
  headers.append("Set-Cookie", `${name}=${signed}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAgeSec}`);
}

export async function getSignedCookie(req, name, secret) {
  const raw = getCookie(req, name);
  if (!raw) return null;
  const value = await verifyCookie(raw, secret);
  if (!value) return null;
  try {
    return JSON.parse(dec.decode(b64uDecode(value)));
  } catch {
    return null;
  }
}

export function clearCookie(headers, name) {
  headers.append("Set-Cookie", `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
}

export function randomB64u(n = 32) {
  return b64uEncode(crypto.getRandomValues(new Uint8Array(n)));
}

export async function pkcePair() {
  const verifier = randomB64u(64);
  const digest = await crypto.subtle.digest("SHA-256", enc.encode(verifier));
  return { verifier, challenge: b64uEncode(new Uint8Array(digest)) };
}
