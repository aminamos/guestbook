// auth/bluesky.js — "Sign in with Bluesky" (atproto OAuth) for Cloudflare Workers.
//
// Implements the atproto OAuth flow for a public client:
//   handle -> DID -> PDS -> authorization-server metadata -> PAR -> authorize
//   -> callback -> DPoP-bound token -> profile
// See https://docs.bsky.app/docs/advanced-guides/oauth-client
//
// Mount the handlers (see auth/README.md), host auth/client-metadata.json at
// /oauth/client-metadata.json, and set env:
//   [vars]            BASE_URL = "https://your-worker.workers.dev"
//   wrangler secret:  SESSION_SECRET
//
// After login, a signed `bsky_user` cookie holds { did, handle, displayName }.

import {
  pkcePair, randomB64u, b64uEncode,
  setSignedCookie, getSignedCookie, clearCookie,
} from "./session.js";

const enc = new TextEncoder();
const APPVIEW = "https://public.api.bsky.app";

function need(env, k) {
  const v = env[k];
  if (!v) throw new Error(`missing env ${k} — see auth/README.md`);
  return v;
}

export const clientId = (env) => need(env, "BASE_URL") + "/oauth/client-metadata.json";
export const redirectUri = (env) => need(env, "BASE_URL") + "/auth/bsky/callback";

function redirectWith(headers, location) {
  headers.set("Location", location);
  return new Response(null, { status: 302, headers });
}

// --- handle / DID / PDS resolution -----------------------------------------

async function resolveHandle(handle) {
  const r = await fetch(
    APPVIEW + "/xrpc/com.atproto.identity.resolveHandle?handle=" + encodeURIComponent(handle)
  );
  if (!r.ok) throw new Error("unknown handle");
  return (await r.json()).did;
}

async function didDocument(did) {
  let url;
  if (did.startsWith("did:plc:")) url = "https://plc.directory/" + did;
  else if (did.startsWith("did:web:")) url = "https://" + did.slice("did:web:".length) + "/.well-known/did.json";
  else throw new Error("unsupported DID method");
  const r = await fetch(url);
  if (!r.ok) throw new Error("could not fetch DID document");
  return r.json();
}

function pdsFromDoc(doc) {
  const svc = (doc.service || []).find(
    (s) => s.id === "#atproto_pds" || String(s.type || "").includes("AtprotoPersonalDataServer")
  );
  if (!svc?.serviceEndpoint) throw new Error("no PDS in DID document");
  return String(svc.serviceEndpoint).replace(/\/$/, "");
}

async function authServerMeta(pds) {
  const r = await fetch(pds + "/.well-known/oauth-authorization-server");
  if (!r.ok) throw new Error("PDS has no OAuth metadata");
  return r.json();
}

// --- DPoP -------------------------------------------------------------------
// Every OAuth + API request is signed with an ES256 key we generate per login.
// The private JWK rides in the signed session cookie (small, ~200 bytes).

async function dpopProof(privateJwk, method, url, nonce) {
  const key = await crypto.subtle.importKey(
    "jwk", privateJwk, { name: "ECDSA", namedCurve: "P-256" }, false, ["sign"]
  );
  const { d, ...pub } = privateJwk; // public half goes in the JWT header
  const header = { typ: "dpop+jwt", alg: "ES256", jwk: pub };
  const payload = {
    htm: method,
    htu: url,
    iat: Math.floor(Date.now() / 1000),
    jti: randomB64u(16),
    ...(nonce ? { nonce } : {}),
  };
  const input =
    b64uEncode(enc.encode(JSON.stringify(header))) + "." +
    b64uEncode(enc.encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign({ name: "ECDSA", hash: "SHA-256" }, key, enc.encode(input));
  return input + "." + b64uEncode(new Uint8Array(sig));
}

// --- routes -----------------------------------------------------------------

// GET /auth/bsky/start?handle=someone.bsky.social
export async function handleBskyStart(req, env) {
  const base = need(env, "BASE_URL");
  const url = new URL(req.url);
  const fail = (m) => Response.redirect(base + "/?bsky_error=" + encodeURIComponent(m), 302);
  const handle = (url.searchParams.get("handle") || "").trim().replace(/^@/, "");
  if (!handle) return fail("missing ?handle=");

  try {
    const did = await resolveHandle(handle);
    const pds = pdsFromDoc(await didDocument(did));
    const meta = await authServerMeta(pds);
    const { pushed_authorization_request_endpoint: parUrl, authorization_endpoint: authUrl, token_endpoint: tokenUrl } = meta;
    if (!parUrl || !authUrl || !tokenUrl) throw new Error("incomplete OAuth metadata");

    const { verifier, challenge } = await pkcePair();
    const state = randomB64u(16);
    const keypair = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: "P-256" }, true, ["sign"]);
    const dpopJwk = await crypto.subtle.exportKey("jwk", keypair.privateKey);

    const parBody = new URLSearchParams({
      response_type: "code",
      client_id: clientId(env),
      redirect_uri: redirectUri(env),
      scope: "atproto transition:generic",
      code_challenge: challenge,
      code_challenge_method: "S256",
      state,
      login_hint: handle,
    });
    // PAR must be DPoP-signed; the PDS may answer use_dpop_nonce on the
    // first try, in which case we retry once with the provided nonce.
    const doPar = async (nonce) =>
      fetch(parUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          DPoP: await dpopProof(dpopJwk, "POST", parUrl, nonce),
        },
        body: parBody,
      });

    let parRes = await doPar();
    if (parRes.status === 400) {
      const err = await parRes.clone().json().catch(() => ({}));
      const nonce = parRes.headers.get("DPoP-Nonce");
      if (err.error === "use_dpop_nonce" && nonce) parRes = await doPar(nonce);
    }
    if (!parRes.ok) throw new Error("PAR failed: " + (await parRes.text()).slice(0, 160));
    const { request_uri } = await parRes.json();

    const headers = new Headers();
    await setSignedCookie(
      headers, "bsky_oauth",
      { dpop: dpopJwk, verifier, state, tokenUrl, pds, did },
      need(env, "SESSION_SECRET"), 600
    );
    return redirectWith(
      headers,
      authUrl + "?client_id=" + encodeURIComponent(clientId(env)) +
        "&request_uri=" + encodeURIComponent(request_uri)
    );
  } catch (e) {
    return fail(e.message);
  }
}

// GET /auth/bsky/callback — the PDS redirects here with ?code=&state=&iss=
export async function handleBskyCallback(req, env) {
  const base = need(env, "BASE_URL");
  const url = new URL(req.url);
  const headers = new Headers();
  clearCookie(headers, "bsky_oauth");
  const fail = (m) => redirectWith(headers, base + "/?bsky_error=" + encodeURIComponent(m));

  const saved = await getSignedCookie(req, "bsky_oauth", need(env, "SESSION_SECRET"));
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!saved || !code || state !== saved.state) return fail("bad oauth state — try again");

  try {
    const body = new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: redirectUri(env),
      client_id: clientId(env),
      code_verifier: saved.verifier,
    });
    const doToken = async (nonce) =>
      fetch(saved.tokenUrl, {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          DPoP: await dpopProof(saved.dpop, "POST", saved.tokenUrl, nonce),
        },
        body,
      });
    let tokRes = await doToken();
    if (tokRes.status === 400) {
      const err = await tokRes.clone().json().catch(() => ({}));
      const nonce = tokRes.headers.get("DPoP-Nonce");
      if (err.error === "use_dpop_nonce" && nonce) tokRes = await doToken(nonce);
    }
    if (!tokRes.ok) throw new Error("token exchange failed: " + (await tokRes.text()).slice(0, 160));
    const tok = await tokRes.json();

    // Profile lives on the user's PDS; the token is DPoP-bound so every
    // call needs a fresh proof signed with the same key.
    const actor = tok.sub || saved.did;
    const profUrl = saved.pds + "/xrpc/app.bsky.actor.getProfile?actor=" + encodeURIComponent(actor);
    const profRes = await fetch(profUrl, {
      headers: {
        Authorization: "DPoP " + tok.access_token,
        DPoP: await dpopProof(saved.dpop, "GET", profUrl),
      },
    });
    let profile = { did: actor, handle: "", displayName: "" };
    if (profRes.ok) {
      const p = await profRes.json();
      profile = { did: p.did, handle: p.handle || "", displayName: p.displayName || "" };
    }

    await setSignedCookie(headers, "bsky_user", profile, need(env, "SESSION_SECRET"), 60 * 60 * 24 * 30);
    return redirectWith(headers, base + "/?hello=@" + encodeURIComponent(profile.handle || profile.did));
  } catch (e) {
    return fail(e.message);
  }
}

// GET /auth/bsky/logout
export async function handleBskyLogout(req, env) {
  const headers = new Headers();
  clearCookie(headers, "bsky_user");
  return redirectWith(headers, need(env, "BASE_URL") + "/");
}

// Read the logged-in Bluesky user inside any handler. Null when signed out.
export function getBskyUser(req, env) {
  if (!env.SESSION_SECRET) return Promise.resolve(null);
  return getSignedCookie(req, "bsky_user", env.SESSION_SECRET);
}
