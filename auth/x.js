// auth/x.js — "Sign in with X" for Cloudflare Workers (OAuth 2.0 + PKCE).
//
// Drop-in template: mount the three handlers in your worker (see auth/README.md),
// set the env vars, register the callback URL in the X developer portal.
//
//   [vars]            BASE_URL = "https://your-worker.workers.dev"
//   wrangler secret:  SESSION_SECRET, X_CLIENT_ID, X_CLIENT_SECRET
//
// After login, a signed `x_user` cookie holds { id, name, username }.
// Adapted from a local Python helper into a proper web flow.

import {
  pkcePair, randomB64u,
  setSignedCookie, getSignedCookie, clearCookie,
} from "./session.js";

const AUTHORIZE_URL = "https://x.com/i/oauth2/authorize";
const TOKEN_URL = "https://api.x.com/2/oauth2/token";
const ME_URL = "https://api.x.com/2/users/me";
const SCOPES = ["tweet.read", "users.read", "offline.access"];

function need(env, k) {
  const v = env[k];
  if (!v) throw new Error(`missing env ${k} — see auth/README.md`);
  return v;
}

function redirectWith(headers, location) {
  headers.set("Location", location);
  return new Response(null, { status: 302, headers });
}

// GET /auth/x/start — begin login
export async function handleXStart(req, env) {
  const { verifier, challenge } = await pkcePair();
  const state = randomB64u(16);
  const headers = new Headers();
  await setSignedCookie(headers, "x_oauth", { verifier, state }, need(env, "SESSION_SECRET"), 600);
  const url = AUTHORIZE_URL + "?" + new URLSearchParams({
    response_type: "code",
    client_id: need(env, "X_CLIENT_ID"),
    redirect_uri: need(env, "BASE_URL") + "/auth/x/callback",
    scope: SCOPES.join(" "),
    state,
    code_challenge: challenge,
    code_challenge_method: "S256",
  });
  return redirectWith(headers, url);
}

// GET /auth/x/callback — X redirects here with ?code=&state=
export async function handleXCallback(req, env) {
  const base = need(env, "BASE_URL");
  const url = new URL(req.url);
  const headers = new Headers();
  clearCookie(headers, "x_oauth");
  const fail = (msg) => redirectWith(headers, base + "/?x_error=" + encodeURIComponent(msg));

  const saved = await getSignedCookie(req, "x_oauth", need(env, "SESSION_SECRET"));
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  if (!saved || !code || state !== saved.state) return fail("bad oauth state — try again");

  const basic = btoa(`${need(env, "X_CLIENT_ID")}:${need(env, "X_CLIENT_SECRET")}`);
  const tokRes = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Authorization: "Basic " + basic,
    },
    body: new URLSearchParams({
      grant_type: "authorization_code",
      code,
      redirect_uri: base + "/auth/x/callback",
      code_verifier: saved.verifier,
      client_id: need(env, "X_CLIENT_ID"),
    }),
  });
  if (!tokRes.ok) return fail("token exchange failed");
  const tok = await tokRes.json();

  const meRes = await fetch(ME_URL, {
    headers: { Authorization: "Bearer " + tok.access_token },
  });
  if (!meRes.ok) return fail("could not fetch profile");
  const me = (await meRes.json()).data;

  await setSignedCookie(
    headers, "x_user",
    { id: me.id, name: me.name, username: me.username },
    need(env, "SESSION_SECRET"), 60 * 60 * 24 * 30
  );
  return redirectWith(headers, base + "/?hello=@" + encodeURIComponent(me.username));
}

// GET /auth/x/logout
export async function handleXLogout(req, env) {
  const headers = new Headers();
  clearCookie(headers, "x_user");
  return redirectWith(headers, need(env, "BASE_URL") + "/");
}

// Read the logged-in X user inside any handler. Returns null when signed out.
export function getXUser(req, env) {
  if (!env.SESSION_SECRET) return Promise.resolve(null);
  return getSignedCookie(req, "x_user", env.SESSION_SECRET);
}
