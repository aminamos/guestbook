# xX_guestbook_Xx 📖✨

A retro 2000s-MySpace-vibe website guestbook + guest counter, running as a
Cloudflare Worker with D1. Thx 4 the add!!1

**Live demo:** https://guestbook.a-8c6.workers.dev

## Embed on any site

```html
<div id="guestbook"></div>
<script src="https://guestbook.a-8c6.workers.dev/embed.js"></script>
```

That's it. The widget renders the full MySpace experience: glitter title,
odometer visitor counter, rainbow dividers, Comic Sans, kaomoji moods.

## API

| Method | Route | What |
|---|---|---|
| `GET` | `/api/count` | `{"count": N}` — the guest counter |
| `GET` | `/api/entries?limit=50&before=<id>` | newest-first entries |
| `POST` | `/api/sign` | `{name, message, website?}` signs the book |
| `DELETE` | `/api/entries/:id` | moderation (needs `X-Admin-Secret`) |
| `GET` | `/embed.js` | the drop-in widget |
| `GET` | `/` | demo page (full MySpace profile parody) |

Spam armor: honeypot field, 5 signs/hour per IP, length caps. No accounts,
no tracking, no cookies.

## auth/ — optional sign-in templates

Drop-in, dependency-free sign-in for Cloudflare Workers (Web Crypto only,
signed-cookie sessions, no KV needed). Not wired into the guestbook by
default — mount the routes you want:

- **Sign in with X** (`auth/x.js`) — OAuth 2.0 + PKCE, adapted from a local helper
- **Sign in with Bluesky** (`auth/bluesky.js`) — atproto OAuth + DPoP, any handle on any PDS

See [auth/README.md](auth/README.md) for setup.

## Run your own

```bash
npm install
npx wrangler d1 create guestbook   # paste database_id into wrangler.toml
npx wrangler d1 migrations apply guestbook --remote
echo -n "your-secret" | npx wrangler secret put ADMIN_SECRET
echo -n "your-salt" | npx wrangler secret put IP_SALT
npx wrangler deploy
```

## Vibe

~*~ best viewed in Internet Explorer 6 @ 800x600 ~*~ ⛔ no haters
