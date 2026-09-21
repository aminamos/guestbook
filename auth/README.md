# auth/ — drop-in sign-in templates for Cloudflare Workers

Two optional identity templates. Neither is wired into the guestbook by
default — mount the routes you want and you're done. Both are dependency-free
(Web Crypto only) and keep sessions in HMAC-signed cookies, so there's no KV
or D1 needed.

| file | what |
|---|---|
| `session.js` | shared signed-cookie sessions, PKCE helpers |
| `x.js` | **Sign in with X** — OAuth 2.0 + PKCE |
| `bluesky.js` | **Sign in with Bluesky** — atproto OAuth + DPoP |
| `client-metadata.json` | Bluesky client metadata (host at `/oauth/client-metadata.json`) |

## Setup

```toml
# wrangler.toml
[vars]
BASE_URL = "https://your-worker.workers.dev"
```

```bash
# secrets — never commit these
npx wrangler secret put SESSION_SECRET   # any long random string
npx wrangler secret put X_CLIENT_ID      # from the X developer portal
npx wrangler secret put X_CLIENT_SECRET  # from the X developer portal
```

## Mount the routes

```js
import { handleXStart, handleXCallback, handleXLogout, getXUser } from "./auth/x.js";
import { handleBskyStart, handleBskyCallback, handleBskyLogout, getBskyUser } from "./auth/bluesky.js";
import CLIENT_META from "./auth/client-metadata.json"; // via `import ... assert` or inline

if (path === "/auth/x/start") return handleXStart(req, env);
if (path === "/auth/x/callback") return handleXCallback(req, env);
if (path === "/auth/x/logout") return handleXLogout(req, env);

if (path === "/auth/bsky/start") return handleBskyStart(req, env);       // ?handle=you.bsky.social
if (path === "/auth/bsky/callback") return handleBskyCallback(req, env);
if (path === "/auth/bsky/logout") return handleBskyLogout(req, env);

if (path === "/oauth/client-metadata.json")
  return Response.json(CLIENT_META, { headers: { "Content-Type": "application/json" } });
```

Read the user anywhere:

```js
const xUser = await getXUser(req, env);       // { id, name, username } | null
const bskyUser = await getBskyUser(req, env); // { did, handle, displayName } | null
```

## X notes

- In the [X developer portal](https://developer.x.com), enable **OAuth 2.0** on
  your app and register the exact redirect URI:
  `https://your-worker.workers.dev/auth/x/callback`
- Scopes requested: `tweet.read users.read offline.access` (read-only; drop
  `offline.access` if you don't need refresh tokens).

## Bluesky notes

- Replace `YOUR_DOMAIN` in `client-metadata.json` with your real domain and
  serve it at `/oauth/client-metadata.json`. The `client_id` **is** that URL —
  atproto requires it to be an HTTPS URL hosting this exact document.
- Login starts at `/auth/bsky/start?handle=you.bsky.social`. Any handle on any
  PDS works: the template resolves handle → DID → PDS → the PDS's own
  authorization server, so custom-domain handles are fine.
- Tokens are DPoP-bound: every API call signs a fresh proof with the per-login
  ES256 key (kept in the signed session cookie). The template handles the
  `use_dpop_nonce` retry for you.
- Spec: https://docs.bsky.app/docs/advanced-guides/oauth-client
