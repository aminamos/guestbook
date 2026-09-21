/**
 * guestbook — a retro website guestbook + guest counter.
 *
 * API:
 *   GET  /api/count                    -> {"count": N}              (optional ?wall=<handle>)
 *   GET  /api/entries?limit=50&before= -> newest-first entries      (optional ?wall=<handle>)
 *   POST /api/sign {name,message,website?,hp?,wall?} -> signs the book (wall must exist)
 *   DELETE /api/entries/:id (x-admin-secret) -> moderate
 *   GET  /api/walls/:handle            -> wall profile + top8
 *   POST /api/walls/:handle/top8 (x-admin-secret)    -> {top8:[{name,url?,note?}]} max 8
 *   POST /api/walls/:handle/profile (x-admin-secret) -> {profile:{mood,currently,interests,heroes,about}}
 *   GET  /embed.js                     -> drop-in widget script (supports <div id="guestbook" data-wall="...">)
 *   GET  /                            -> demo page
 *   GET  /:handle                      -> personal wall page (if wall exists)
 */

const MAX_NAME = 60;
const MAX_MSG = 500;
const MAX_SITE = 200;
const RATE_LIMIT_WINDOW = 3600; // seconds
const RATE_LIMIT_MAX = 5;

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, POST, DELETE, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, X-Admin-Secret",
};

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...CORS },
  });
}

function esc(s) {
  return String(s ?? "")
    .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

async function sha256hex(s) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function clientIp(req) {
  return req.headers.get("CF-Connecting-IP") || "unknown";
}

const HANDLE_RE = /^[a-z0-9_]{1,30}$/i;

async function wallExists(env, handle) {
  const w = await env.DB.prepare("SELECT handle FROM walls WHERE handle = ?")
    .bind(handle).first();
  return !!w;
}

async function handleSign(req, env) {
  let body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "invalid JSON" }, 400);
  }
  // honeypot: bots fill it, humans don't
  if (body.hp) return json({ ok: true, id: 0 }); // pretend success

  const name = String(body.name ?? "").trim().slice(0, MAX_NAME);
  const message = String(body.message ?? "").trim().slice(0, MAX_MSG);
  let website = String(body.website ?? "").trim().slice(0, MAX_SITE);

  if (!name) return json({ error: "name is required" }, 400);
  if (!message) return json({ error: "message is required" }, 400);
  if (website && !/^https?:\/\//i.test(website)) website = "https://" + website;
  if (website && website.length > MAX_SITE) return json({ error: "website too long" }, 400);

  let wall = String(body.wall ?? "").trim().toLowerCase().slice(0, 30) || null;
  if (wall) {
    if (!HANDLE_RE.test(wall)) return json({ error: "bad wall" }, 400);
    if (!(await wallExists(env, wall))) return json({ error: "wall not found" }, 404);
  }

  const ipHash = await sha256hex(clientIp(req) + (env.IP_SALT || "guestbook"));
  const now = Math.floor(Date.now() / 1000);

  const recent = await env.DB.prepare(
    "SELECT COUNT(*) AS n FROM entries WHERE ip_hash = ? AND created_at > ?"
  ).bind(ipHash, now - RATE_LIMIT_WINDOW).first();
  if (recent && recent.n >= RATE_LIMIT_MAX) {
    return json({ error: "slow down — try again later" }, 429);
  }

  const res = await env.DB.prepare(
    "INSERT INTO entries (name, message, website, wall, created_at, ip_hash) VALUES (?, ?, ?, ?, ?, ?)"
  ).bind(name, message, website || null, wall, now, ipHash).run();

  return json(
    { ok: true, id: Number(res.meta.last_row_id), name, message, website: website || null, wall, created_at: now },
    201
  );
}

async function handleEntries(req, env) {
  const url = new URL(req.url);
  const limit = Math.min(Math.max(parseInt(url.searchParams.get("limit") || "50", 10) || 50, 1), 200);
  const before = parseInt(url.searchParams.get("before") || "0", 10) || 0;
  const wall = (url.searchParams.get("wall") || "").toLowerCase();
  if (wall && !HANDLE_RE.test(wall)) return json({ error: "bad wall" }, 400);

  const wallCond = wall ? "wall = ?" : "wall IS NULL";
  const wallBind = wall ? [wall] : [];
  let q, binds;
  if (before) {
    q = `SELECT id, name, message, website, created_at FROM entries WHERE ${wallCond} AND id < ? ORDER BY id DESC LIMIT ?`;
    binds = [...wallBind, before, limit];
  } else {
    q = `SELECT id, name, message, website, created_at FROM entries WHERE ${wallCond} ORDER BY id DESC LIMIT ?`;
    binds = [...wallBind, limit];
  }
  const rows = await env.DB.prepare(q).bind(...binds).all();
  return json({ entries: rows.results || [] });
}

async function handleDelete(req, env, id) {
  const secret = req.headers.get("X-Admin-Secret");
  if (!secret || secret !== env.ADMIN_SECRET) return json({ error: "nope" }, 403);
  await env.DB.prepare("DELETE FROM entries WHERE id = ?").bind(id).run();
  return json({ ok: true });
}

function checkAdmin(req, env) {
  const secret = req.headers.get("X-Admin-Secret");
  return secret && secret === env.ADMIN_SECRET;
}

async function getWall(env, handle) {
  const w = await env.DB.prepare(
    "SELECT handle, display_name, profile_json, top8 FROM walls WHERE handle = ?"
  ).bind(handle.toLowerCase()).first();
  if (!w) return null;
  let profile = {}, top8 = [];
  try { profile = JSON.parse(w.profile_json || "{}"); } catch {}
  try { top8 = JSON.parse(w.top8 || "[]"); } catch {}
  return { handle: w.handle, display_name: w.display_name, profile, top8 };
}

async function handleWallGet(env, handle) {
  const w = await getWall(env, handle);
  if (!w) return json({ error: "wall not found" }, 404);
  return json(w);
}

async function handleWallTop8(req, env, handle) {
  if (!checkAdmin(req, env)) return json({ error: "nope" }, 403);
  const h = handle.toLowerCase();
  if (!(await wallExists(env, h))) return json({ error: "wall not found" }, 404);
  let body;
  try { body = await req.json(); } catch { return json({ error: "invalid JSON" }, 400); }
  const top8 = body.top8;
  if (!Array.isArray(top8) || top8.length > 8) return json({ error: "top8 must be an array of at most 8" }, 400);
  const clean = [];
  for (const t of top8) {
    const name = String(t?.name ?? "").trim().slice(0, MAX_NAME);
    if (!name) return json({ error: "every top8 entry needs a name" }, 400);
    let url = String(t?.url ?? "").trim().slice(0, MAX_SITE);
    if (url && !/^https?:\/\//i.test(url)) url = "https://" + url;
    const note = String(t?.note ?? "").trim().slice(0, 120);
    clean.push({ name, url: url || null, note: note || null });
  }
  await env.DB.prepare("UPDATE walls SET top8 = ? WHERE handle = ?")
    .bind(JSON.stringify(clean), h).run();
  return json({ ok: true, top8: clean });
}

const PROFILE_FIELDS = ["mood", "currently", "interests", "heroes", "about"];

async function handleWallProfile(req, env, handle) {
  if (!checkAdmin(req, env)) return json({ error: "nope" }, 403);
  const h = handle.toLowerCase();
  const existing = await getWall(env, h);
  if (!existing) return json({ error: "wall not found" }, 404);
  let body;
  try { body = await req.json(); } catch { return json({ error: "invalid JSON" }, 400); }
  const profile = { ...existing.profile };
  const incoming = body.profile || {};
  for (const f of PROFILE_FIELDS) {
    if (incoming[f] !== undefined) profile[f] = String(incoming[f]).slice(0, 200);
  }
  await env.DB.prepare("UPDATE walls SET profile_json = ? WHERE handle = ?")
    .bind(JSON.stringify(profile), h).run();
  return json({ ok: true, profile });
}

function embedJs(base) {
  return `/* guestbook embed — drop this on any page: <div id="guestbook"></div><script src="${base}/embed.js"><\/script> */
(function(){
var BASE=${JSON.stringify(base)};
var CSS=[
".gb-wrap{font-family:'Comic Sans MS','Comic Sans',cursive;background:#000 url('') repeat;color:#ff99ff;",
" background-image:radial-gradient(#ff00ff 1px,transparent 1.5px),radial-gradient(#00ffff 1px,transparent 1.5px);",
" background-size:28px 28px;background-position:0 0,14px 14px;",
" border:4px ridge #ff00ff;padding:14px;max-width:520px;}",
".gb-glitter{font-size:26px;font-weight:bold;text-align:center;margin:0 0 4px;",
" background:linear-gradient(90deg,#ff0000,#ff9900,#ffff00,#33ff33,#00ffff,#9900ff,#ff00ff);",
" -webkit-background-clip:text;background-clip:text;color:transparent;",
" filter:drop-shadow(1px 1px 0 #fff);animation:gbhue 4s linear infinite;}",
"@keyframes gbhue{to{filter:hue-rotate(360deg) drop-shadow(1px 1px 0 #fff);}}",
".gb-blink{text-align:center;color:#00ff00;animation:gbblink 1s steps(2) infinite;font-size:14px;}",
"@keyframes gbblink{50%{opacity:0;}}",
".gb-counter{text-align:center;margin:8px 0;}",
".gb-counter .digits{display:inline-block;background:#000;border:2px inset #888;padding:2px 6px;}",
".gb-counter .digits span{display:inline-block;background:#111;color:#39ff14;font-family:'Courier New',monospace;",
" font-weight:bold;font-size:20px;padding:0 4px;margin:0 1px;border:1px solid #333;}",
".gb-counter small{display:block;color:#ffff00;margin-top:2px;}",
".gb-hr{border:0;height:6px;margin:10px 0;",
" background:repeating-linear-gradient(90deg,#ff0000 0 12px,#ff9900 12px 24px,#ffff00 24px 36px,#33ff33 36px 48px,#00ffff 48px 60px,#9900ff 60px 72px);}",
".gb-form input,.gb-form textarea{display:block;width:100%;box-sizing:border-box;margin:6px 0;padding:6px;",
" font-family:'Comic Sans MS',cursive;background:#ffffcc;border:2px inset #ff99ff;color:#000;}",
".gb-form textarea{min-height:70px;}",
".gb-form button{font-family:'Comic Sans MS',cursive;font-weight:bold;font-size:16px;cursor:pointer;",
" background:linear-gradient(#ffccff,#ff66cc);border:3px outset #ff99ff;color:#660066;padding:4px 18px;}",
".gb-form button:active{border-style:inset;}",
".gb-msg{color:#00ff00;margin-left:8px;}",
".gb-entry{background:#1a001a;border:2px groove #ff00ff;margin:8px 0;padding:8px;color:#ffccff;}",
".gb-entry b{color:#ffff00;}",
".gb-entry .gb-date{color:#00ffff;font-size:12px;}",
".gb-entry p{margin:4px 0;color:#ffffff;}",
".gb-entry a{color:#00ff00;}",
".gb-mood{color:#ff99ff;font-size:12px;}",
".gb-footer{text-align:center;color:#00ffff;font-size:12px;margin-top:10px;}"
].join("\\n");
function esc(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
var el=document.getElementById("guestbook"); if(!el) return;
var WALL=el.getAttribute("data-wall")||"";
var QS=WALL?("wall="+encodeURIComponent(WALL)):"";
var st=document.createElement("style"); st.textContent=CSS; document.head.appendChild(st);
var moods=["(◕‿◕✿)","(ﾉ◕ヮ◕)ﾉ*:･ﾟ✧","♥‿♥","(づ￣ ³￣)づ","☆彡","(๑˃̵ᴗ˂̵)و"];
el.innerHTML='<div class="gb-wrap">'
 +'<div class="gb-glitter">✨*･ﾟ Guestbook ﾟ･*✨</div>'
 +'<div class="gb-blink">★&nbsp;sign my guestbook or else&nbsp;★</div>'
 +'<div class="gb-counter"><span class="digits"></span><small>visitors 5ince 2005!!1</small></div>'
 +'<hr class="gb-hr">'
 +'<form class="gb-form"><input name="name" maxlength="60" placeholder="ur name xoxo" required>'
 +'<input name="website" maxlength="200" placeholder="ur myspace url (optional)">'
 +'<textarea name="message" maxlength="500" placeholder="leave a comment… thx 4 the add!!" required></textarea>'
 +'<input type="text" name="hp" style="display:none" tabindex="-1" autocomplete="off">'
 +'<button type="submit">💖 sign it!! 💖</button><span class="gb-msg"></span></form>'
 +'<hr class="gb-hr"><div class="gb-entries"></div>'
 +'<div class="gb-footer">~*~ best viewed in IE6 @ 800x600 ~*~<br>no haters plz ⛔</div></div>';
function pad(n,l){n=String(n);while(n.length<(l||6))n="0"+n;return n;}
function counter(n){el.querySelector(".digits").innerHTML=pad(n).split("").map(function(d){return "<span>"+d+"</span>";}).join("");}
function render(list){
 el.querySelector(".gb-entries").innerHTML=list.map(function(e,i){
  var w=e.website?(' <a href="'+esc(e.website)+'" rel="nofollow noopener" target="_blank">[link]</a>'):"";
  var m=moods[e.id%moods.length];
  return '<div class="gb-entry"><b>★ '+esc(e.name)+'</b>'+w+' <span class="gb-mood">'+m+'</span><br>'
   +'<span class="gb-date">posted: '+new Date(e.created_at*1000).toLocaleString()+'</span><p>'+esc(e.message)+'</p></div>';
 }).join("")||'<div class="gb-entry"><p>no1 has signed yet… be the first!!1</p></div>';
}
function refresh(){
 fetch(BASE+"/api/entries?limit=20"+(QS?"&"+QS:"")).then(function(r){return r.json();}).then(function(d){render(d.entries||[]);});
 fetch(BASE+"/api/count"+(QS?"?"+QS:"")).then(function(r){return r.json();}).then(function(d){counter(d.count);});
}
refresh();
el.querySelector(".gb-form").addEventListener("submit",function(ev){
 ev.preventDefault();
 var f=ev.target, msg=el.querySelector(".gb-msg"); msg.textContent="signing…";
 fetch(BASE+"/api/sign",{method:"POST",headers:{"Content-Type":"application/json"},
  body:JSON.stringify({name:f.name.value,website:f.website.value,message:f.message.value,hp:f.hp.value,wall:WALL||undefined})})
 .then(function(r){return r.json().then(function(d){return {ok:r.ok,d:d};});})
 .then(function(res){
  if(res.ok){msg.textContent="thx 4 signing!!1 🎉";f.reset();refresh();}
  else {msg.textContent=res.d.error||"oops";}
 }).catch(function(){msg.textContent="oops, try again";});
});
})();`;
}

function demoPage(base) {
  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>xX_guestbook_Xx</title>
<style>
body{font-family:'Comic Sans MS','Comic Sans',cursive;color:#ff99ff;margin:0;padding:0;
 background:#000;
 background-image:radial-gradient(#ff00ff 1.2px,transparent 1.6px),radial-gradient(#00ffff 1.2px,transparent 1.6px);
 background-size:30px 30px;background-position:0 0,15px 15px;}
.wrap{max-width:760px;margin:0 auto;padding:10px;}
.profile{border:4px ridge #00ffff;background:#0a0a2a;padding:12px;margin-bottom:14px;}
.p-head{display:flex;gap:12px;align-items:center;}
.avatar{width:110px;height:110px;border:3px outset #ff00ff;background:linear-gradient(135deg,#ff00ff,#00ffff);
 display:flex;align-items:center;justify-content:center;font-size:56px;flex-shrink:0;}
.p-name{font-size:30px;color:#ffff00;text-shadow:2px 2px #ff00ff;margin:0;}
.p-status{color:#00ff00;animation:gbblink 1s steps(2) infinite;}
@keyframes gbblink{50%{opacity:0;}}
table.details{border-collapse:collapse;margin-top:10px;width:100%;}
table.details td{border:2px groove #ff00ff;padding:5px 8px;background:#1a001a;color:#ffccff;font-size:14px;}
table.details td.k{color:#00ffff;width:130px;}
.marquee{background:#ffff00;color:#ff0000;font-weight:bold;padding:4px;white-space:nowrap;overflow:hidden;}
.marquee span{display:inline-block;animation:scroll 12s linear infinite;}
@keyframes scroll{from{transform:translateX(100%);}to{transform:translateX(-100%);}}
.embedbox{border:4px ridge #ff00ff;background:#1a001a;padding:12px;margin-bottom:14px;}
.embedbox h2{color:#00ffff;margin:0 0 8px;}
pre{background:#000;color:#39ff14;padding:10px;overflow-x:auto;font-size:13px;border:2px inset #333;}
.top8 h2{color:#ffff00;text-shadow:2px 2px #ff00ff;margin:0 0 8px;text-align:center;}
.top8-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;}
.top8-cell{border:3px outset #ff99ff;background:#2a002a;text-align:center;padding:8px;font-size:13px;color:#ffccff;min-height:70px;}
.top8-cell .face{font-size:34px;}
.footer{text-align:center;color:#00ffff;font-size:12px;margin:16px 0;}
</style></head><body><div class="wrap">

<div class="marquee"><span>★☆★ WELCOME TO MY GUESTBOOK ★☆★ THX 4 THE ADD ★☆★ SIGN OR BE SQUARE ★☆★</span></div>

<div class="profile">
 <div class="p-head">
  <div class="avatar">📖</div>
  <div>
   <p class="p-name">xX_guestbook_Xx</p>
   <p class="p-status">● online now!!</p>
  </div>
 </div>
 <table class="details">
  <tr><td class="k">Mood</td><td>nostalgic (◕‿◕✿)</td></tr>
  <tr><td class="k">Currently</td><td>counting visitors like it's 2005</td></tr>
  <tr><td class="k">Interests</td><td>glitter text, guest counters, under construction gifs</td></tr>
  <tr><td class="k">Heroes</td><td>Tom (ur first friend)</td></tr>
 </table>
</div>

<div class="embedbox">
 <h2>💾 put this on ur site 💾</h2>
 <pre>&lt;div id="guestbook"&gt;&lt;/div&gt;
&lt;script src="${esc(base)}/embed.js"&gt;&lt;/script&gt;</pre>
 <div id="guestbook"></div>
 <script src="${esc(base)}/embed.js"></script>
</div>

<div class="top8">
 <h2>✨ my top 8 signers ✨</h2>
 <div class="top8-grid" id="top8"></div>
</div>

<div class="footer">~*~ best viewed in Internet Explorer 6 @ 800x600 ~*~<br>© 2005-2026 xX_guestbook_Xx ⛔ no haters</div>
</div>
<script>
fetch("${esc(base)}/api/entries?limit=8").then(r=>r.json()).then(d=>{
 const faces=["🦊","🐼","🐸","🦄","🐙","🐝","🦋","🐢"];
 document.getElementById("top8").innerHTML=(d.entries||[]).map((e,i)=>
  '<div class="top8-cell"><div class="face">'+faces[i%8]+'</div>'+
  String(e.name||"").replace(/&/g,"&amp;").replace(/</g,"&lt;")+"</div>").join("")
  ||'<div class="top8-cell">empty…<br>sign 2 claim a spot!!</div>';
});
</script>
</body></html>`;
}

function wallPage(base, wall) {
  const p = wall.profile || {};
  const rows = [["Mood", p.mood], ["Currently", p.currently], ["Interests", p.interests],
                ["Heroes", p.heroes], ["About", p.about]]
    .filter(([, v]) => v)
    .map(([k, v]) => '<tr><td class="k">' + esc(k) + "</td><td>" + esc(v) + "</td></tr>")
    .join("");
  const faces = ["🦊", "🐼", "🐸", "🦄", "🐙", "🐝", "🦋", "🐢"];
  const top8cells = (wall.top8 || []).slice(0, 8).map((t, i) => {
    const inner = '<div class="face">' + faces[i % 8] + '</div><div class="tname">' + esc(t.name) + "</div>"
      + (t.note ? '<div class="tnote">' + esc(t.note) + "</div>" : "");
    return '<div class="top8-cell">' + (t.url
      ? '<a href="' + esc(t.url) + '" rel="nofollow noopener" target="_blank">' + inner + "</a>"
      : inner) + "</div>";
  }).join("") || '<div class="top8-cell">empty…<br>the owner is picky</div>';

  const handleJs = JSON.stringify(wall.handle);
  const profileJs = JSON.stringify(p).replace(/</g, "\\u003c");
  const top8Js = JSON.stringify(wall.top8 || []).replace(/</g, "\\u003c");
  const baseJs = JSON.stringify(base);

  return `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>${esc(wall.display_name)} xX_wall_Xx</title>
<style>
body{font-family:'Comic Sans MS','Comic Sans',cursive;color:#ff99ff;margin:0;padding:0;
 background:#000;
 background-image:radial-gradient(#ff00ff 1.2px,transparent 1.6px),radial-gradient(#00ffff 1.2px,transparent 1.6px);
 background-size:30px 30px;background-position:0 0,15px 15px;}
.wrap{max-width:760px;margin:0 auto;padding:10px;}
.profile{border:4px ridge #00ffff;background:#0a0a2a;padding:12px;margin-bottom:14px;}
.p-head{display:flex;gap:12px;align-items:center;}
.avatar{width:110px;height:110px;border:3px outset #ff00ff;background:linear-gradient(135deg,#ff00ff,#00ffff);
 display:flex;align-items:center;justify-content:center;font-size:56px;flex-shrink:0;}
.p-name{font-size:30px;color:#ffff00;text-shadow:2px 2px #ff00ff;margin:0;word-break:break-word;}
.p-status{color:#00ff00;animation:gbblink 1s steps(2) infinite;}
@keyframes gbblink{50%{opacity:0;}}
table.details{border-collapse:collapse;margin-top:10px;width:100%;}
table.details td{border:2px groove #ff00ff;padding:5px 8px;background:#1a001a;color:#ffccff;font-size:14px;}
table.details td.k{color:#00ffff;width:130px;}
.marquee{background:#ffff00;color:#ff0000;font-weight:bold;padding:4px;white-space:nowrap;overflow:hidden;}
.marquee span{display:inline-block;animation:scroll 12s linear infinite;}
@keyframes scroll{from{transform:translateX(100%);}to{transform:translateX(-100%);}}
.wallbox{border:4px ridge #ff00ff;background:#1a001a;padding:12px;margin-bottom:14px;}
.wallbox h2{color:#00ffff;margin:0 0 8px;}
.top8 h2{color:#ffff00;text-shadow:2px 2px #ff00ff;margin:0 0 8px;text-align:center;}
.top8-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:8px;}
.top8-cell{border:3px outset #ff99ff;background:#2a002a;text-align:center;padding:8px;font-size:13px;color:#ffccff;min-height:70px;}
.top8-cell .face{font-size:34px;}
.top8-cell .tname{font-weight:bold;color:#ffff00;}
.top8-cell .tnote{font-size:11px;color:#ff99ff;}
.top8-cell a{color:inherit;text-decoration:none;}
.ownerbox{border:4px ridge #ffff00;background:#1a1a00;padding:12px;margin-bottom:14px;}
.ownerbox h2,.ownerbox h3{color:#ffff00;margin:10px 0 6px;}
.ownerbox button{font-family:'Comic Sans MS',cursive;font-weight:bold;cursor:pointer;
 background:linear-gradient(#ffffcc,#ffcc00);border:3px outset #ffff99;color:#663300;padding:4px 12px;margin:2px;}
.ownerbox button:active{border-style:inset;}
.ownerbox input{display:block;width:100%;box-sizing:border-box;margin:4px 0;padding:6px;
 font-family:'Comic Sans MS',cursive;background:#ffffcc;border:2px inset #ff99ff;color:#000;}
.t8row{display:flex;justify-content:space-between;align-items:center;background:#2a002a;
 border:2px groove #ff00ff;margin:4px 0;padding:4px 8px;color:#ffccff;}
.cand{font-size:13px;}
.prow label{color:#00ffff;font-size:13px;}
.footer{text-align:center;color:#00ffff;font-size:12px;margin:16px 0;}
.footer a{color:#00ff00;}
</style></head><body><div class="wrap">

<div class="marquee"><span>★☆★ WELCOME TO ${esc(wall.display_name).toUpperCase()}'S WALL ★☆★ THX 4 THE ADD ★☆★ SIGN OR BE SQUARE ★☆★</span></div>

<div class="profile">
 <div class="p-head">
  <div class="avatar">😎</div>
  <div>
   <p class="p-name">${esc(wall.display_name)}</p>
   <p class="p-status">● online now!!</p>
  </div>
 </div>
 <table class="details">${rows}</table>
</div>

<div class="top8">
 <h2>✨ my top 8 ✨</h2>
 <div class="top8-grid">${top8cells}</div>
</div>

<div class="wallbox">
 <h2>💬 sign my wall 💬</h2>
 <div id="guestbook" data-wall="${esc(wall.handle)}"></div>
 <script src="${esc(base)}/embed.js"></script>
</div>

<div class="ownerbox">
 <button id="ownerBtn">🔧 owner? unlock</button>
 <div id="ownerPanel" style="display:none">
  <h2>✏️ top 8 editor</h2>
  <div id="top8edit"></div>
  <div><button id="saveTop8">💾 save top 8</button></div>
  <h3>add from signers</h3>
  <div id="candidates"><p>loading…</p></div>
  <h3>add manually</h3>
  <input id="mName" maxlength="60" placeholder="name">
  <input id="mUrl" maxlength="200" placeholder="url (optional)">
  <div><button id="addManual">+ add</button></div>
  <h2>✏️ profile editor</h2>
  <div class="prow"><label>Mood</label><input id="fMood" maxlength="200"></div>
  <div class="prow"><label>Currently</label><input id="fCurrently" maxlength="200"></div>
  <div class="prow"><label>Interests</label><input id="fInterests" maxlength="200"></div>
  <div class="prow"><label>Heroes</label><input id="fHeroes" maxlength="200"></div>
  <div class="prow"><label>About</label><input id="fAbout" maxlength="200"></div>
  <div><button id="saveProfile">💾 save profile</button></div>
 </div>
</div>

<div class="footer">~*~ best viewed in Internet Explorer 6 @ 800x600 ~*~<br><a href="${esc(base)}/">← back to the main guestbook</a><br>© 2005-2026 ${esc(wall.display_name)} ⛔ no haters</div>
</div>
<script>
(function(){
var HANDLE=${handleJs}, BASE=${baseJs};
var INITIAL_PROFILE=${profileJs}, INITIAL_TOP8=${top8Js};
function escHtml(s){return String(s==null?"":s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;");}
function escAttr(s){return escHtml(s).replace(/'/g,"&#39;");}
var ADMIN=sessionStorage.getItem("gb-admin")||"";
var panel=document.getElementById("ownerPanel"), obtn=document.getElementById("ownerBtn");
function authed(path,body){
 return fetch(BASE+path,{method:"POST",headers:{"Content-Type":"application/json","X-Admin-Secret":ADMIN},body:JSON.stringify(body)})
 .then(function(r){
  if(r.status===403){alert("wrong secret");sessionStorage.removeItem("gb-admin");ADMIN="";location.reload();return null;}
  return r.json();
 });
}
var top8=INITIAL_TOP8.slice();
function renderTop8Editor(){
 var box=document.getElementById("top8edit");
 box.innerHTML=top8.length?top8.map(function(t,i){
  return '<div class="t8row"><span>#'+(i+1)+' '+escHtml(t.name)+(t.note?" ("+escHtml(t.note)+")":"")+"</span>"
   +'<span><button data-a="up" data-i="'+i+'">↑</button>'
   +'<button data-a="dn" data-i="'+i+'">↓</button>'
   +'<button data-a="rm" data-i="'+i+'">✕</button></span></div>';
 }).join(""):"<p>nobody yet. add some!!</p>";
 Array.prototype.forEach.call(box.querySelectorAll("button"),function(b){
  b.onclick=function(){
   var i=+b.getAttribute("data-i"), a=b.getAttribute("data-a"), tmp;
   if(a==="up"&&i>0){tmp=top8[i-1];top8[i-1]=top8[i];top8[i]=tmp;}
   if(a==="dn"&&i<top8.length-1){tmp=top8[i+1];top8[i+1]=top8[i];top8[i]=tmp;}
   if(a==="rm"){top8.splice(i,1);}
   renderTop8Editor();
  };
 });
}
function loadCandidates(){
 fetch(BASE+"/api/entries?wall="+encodeURIComponent(HANDLE)+"&limit=200")
 .then(function(r){return r.json();}).then(function(d){
  var seen={};
  top8.forEach(function(t){seen[String(t.name).toLowerCase()]=1;});
  var names=[];
  (d.entries||[]).forEach(function(e){
   var n=String(e.name||"").trim(), k=n.toLowerCase();
   if(n&&!seen[k]){seen[k]=1;names.push(n);}
  });
  var c=document.getElementById("candidates");
  c.innerHTML=names.length?names.map(function(n){
   return '<button class="cand" data-n="'+escAttr(n)+'">+ '+escHtml(n)+'</button>';
  }).join(""):"<p>no signers yet</p>";
  Array.prototype.forEach.call(c.querySelectorAll(".cand"),function(b){
   b.onclick=function(){
    if(top8.length>=8){alert("top 8 is full!!");return;}
    top8.push({name:b.getAttribute("data-n"),url:null,note:null});
    renderTop8Editor(); loadCandidates();
   };
  });
 }).catch(function(){document.getElementById("candidates").innerHTML="<p>oops, couldnt load</p>";});
}
function initOwner(){
 panel.style.display="block"; obtn.style.display="none";
 ["Mood","Currently","Interests","Heroes","About"].forEach(function(f){
  document.getElementById("f"+f).value=INITIAL_PROFILE[f.toLowerCase()]||"";
 });
 renderTop8Editor(); loadCandidates();
 document.getElementById("addManual").onclick=function(){
  var name=document.getElementById("mName").value.trim();
  if(!name)return;
  if(top8.length>=8){alert("top 8 is full!!");return;}
  top8.push({name:name,url:document.getElementById("mUrl").value.trim()||null,note:null});
  document.getElementById("mName").value="";document.getElementById("mUrl").value="";
  renderTop8Editor();
 };
 document.getElementById("saveTop8").onclick=function(){
  authed("/api/walls/"+HANDLE+"/top8",{top8:top8}).then(function(r){
   if(r&&r.ok){alert("saved!!1 🎉");location.reload();}
   else if(r){alert(r.error||"oops");}
  });
 };
 document.getElementById("saveProfile").onclick=function(){
  authed("/api/walls/"+HANDLE+"/profile",{profile:{
   mood:document.getElementById("fMood").value,
   currently:document.getElementById("fCurrently").value,
   interests:document.getElementById("fInterests").value,
   heroes:document.getElementById("fHeroes").value,
   about:document.getElementById("fAbout").value
  }}).then(function(r){
   if(r&&r.ok){alert("saved!!1 🎉");location.reload();}
   else if(r){alert(r.error||"oops");}
  });
 };
}
obtn.onclick=function(){
 var s=prompt("owner secret:");
 if(!s)return;
 ADMIN=s; sessionStorage.setItem("gb-admin",s); initOwner();
};
if(ADMIN)initOwner();
})();
</script>
</body></html>`;
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;

    if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: CORS });

    if (path === "/api/count" && req.method === "GET") {
      const wall = (url.searchParams.get("wall") || "").toLowerCase();
      if (wall && !HANDLE_RE.test(wall)) return json({ error: "bad wall" }, 400);
      const q = wall
        ? "SELECT COUNT(*) AS n FROM entries WHERE wall = ?"
        : "SELECT COUNT(*) AS n FROM entries WHERE wall IS NULL";
      const row = wall
        ? await env.DB.prepare(q).bind(wall).first()
        : await env.DB.prepare(q).first();
      return json({ count: row ? row.n : 0 });
    }
    if (path === "/api/entries" && req.method === "GET") return handleEntries(req, env);
    if (path === "/api/sign" && req.method === "POST") return handleSign(req, env);

    const del = path.match(/^\/api\/entries\/(\d+)$/);
    if (del && req.method === "DELETE") return handleDelete(req, env, del[1]);

    const wallTop8 = path.match(/^\/api\/walls\/([a-z0-9_]{1,30})\/top8$/i);
    if (wallTop8 && req.method === "POST") return handleWallTop8(req, env, wallTop8[1]);

    const wallProf = path.match(/^\/api\/walls\/([a-z0-9_]{1,30})\/profile$/i);
    if (wallProf && req.method === "POST") return handleWallProfile(req, env, wallProf[1]);

    const wallGet = path.match(/^\/api\/walls\/([a-z0-9_]{1,30})$/i);
    if (wallGet && req.method === "GET") return handleWallGet(env, wallGet[1]);

    if (path === "/embed.js" && req.method === "GET") {
      const base = `${url.protocol}//${url.host}`;
      return new Response(embedJs(base), {
        headers: { "Content-Type": "application/javascript", ...CORS, "Cache-Control": "public, max-age=300" },
      });
    }
    if (path === "/" && req.method === "GET") {
      const base = `${url.protocol}//${url.host}`;
      return new Response(demoPage(base), { headers: { "Content-Type": "text/html" } });
    }

    const wallPageMatch = path.match(/^\/([a-z0-9_]{1,30})$/i);
    if (wallPageMatch && req.method === "GET") {
      const wall = await getWall(env, wallPageMatch[1]);
      if (!wall) return json({ error: "not found" }, 404);
      const base = `${url.protocol}//${url.host}`;
      return new Response(wallPage(base, wall), { headers: { "Content-Type": "text/html" } });
    }
    return json({ error: "not found" }, 404);
  },
};
