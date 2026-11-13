/** Mana Dziesmu Grāmata — Cloudflare Worker playlist sync
 * Bind KV namespace as TOKENS. Configure the variables/secrets listed in wrangler.toml notes.
 */
const SPOTIFY_SCOPES = 'playlist-modify-public playlist-read-private';
const GOOGLE_SCOPES = 'openid email https://www.googleapis.com/auth/youtube';
const SESSION_TTL = 8 * 60 * 60;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const origin = request.headers.get('Origin') || '';
    let allowed = '';
    try { allowed = new URL(env.APP_ORIGIN).origin; } catch {}
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(origin, allowed) });
    try {
      if (url.pathname === '/health' && request.method === 'GET') return json({ ok: true, service: 'songbook-playlist-sync', version: 2 }, 200, origin, allowed);
      if (url.pathname === '/public/playlists' && request.method === 'GET') return json({ ok: true, playlists: await playlistLinks(env) }, 200, origin, allowed);
      if (url.pathname === '/auth/google' && request.method === 'GET') return await googleStart(env);
      if (url.pathname === '/oauth/google/callback' && request.method === 'GET') return await googleCallback(url, env);
      if (url.pathname === '/auth/spotify' && request.method === 'GET') { await requireAdmin(request, env); return await spotifyStart(env, origin, allowed); }
      if (url.pathname === '/oauth/spotify/callback' && request.method === 'GET') return await spotifyCallback(url, env);
      if (url.pathname === '/sync/song' && request.method === 'POST') {
        await requireAdmin(request, env);
        const body = await request.json();
        return json({ ok: true, result: await syncSong(body, env) }, 200, origin, allowed);
      }
      return json({ ok: false, error: 'Not found' }, 404, origin, allowed);
    } catch (e) {
      return json({ ok: false, error: safeError(e) }, e.status || 500, origin, allowed);
    }
  }
};

function cors(origin, allowed) {
  const h = { Vary: 'Origin', 'Access-Control-Allow-Methods': 'GET, POST, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Max-Age': '86400' };
  if (origin && allowed && origin.replace(/\/$/, '') === allowed) h['Access-Control-Allow-Origin'] = origin;
  return h;
}
function json(data, status, origin, allowed) {
  return new Response(JSON.stringify(data), { status, headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...cors(origin, allowed) } });
}
function redirect(url) { return Response.redirect(url, 302); }
function fail(message, status = 400) { const e = new Error(message); e.status = status; throw e; }
function safeError(e) { return String(e?.publicMessage || e?.message || 'Server error').slice(0, 280); }
function requireConfig(env, names) { const missing = names.filter(n => !env[n]); if (missing.length) fail('Worker konfigurācijā trūkst: ' + missing.join(', '), 503); }
function randomHex(n = 24) { const b = crypto.getRandomValues(new Uint8Array(n)); return [...b].map(x => x.toString(16).padStart(2, '0')).join(''); }
async function saveState(env, state, value) { await env.TOKENS.put('oauth:' + state, JSON.stringify(value), { expirationTtl: 600 }); }
async function takeState(env, state, provider) {
  if (!state) fail('Trūkst OAuth state parametra. Sāc autorizāciju no jauna.');
  const key = 'oauth:' + state; const v = await env.TOKENS.get(key, 'json'); await env.TOKENS.delete(key);
  if (!v || v.provider !== provider) fail('OAuth state pārbaude neizdevās. Sāc autorizāciju no jauna.');
  return v;
}
function b64u(bytes) { let s = ''; for (const b of bytes) s += String.fromCharCode(b); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, ''); }
async function signSession(payload, secret) {
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const data = b64u(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(data));
  return data + '.' + b64u(new Uint8Array(sig));
}
async function verifySession(token, secret) {
  if (!token || !secret) fail('Nav derīga administratora sesija.', 401);
  const p = token.split('.'); if (p.length !== 2) fail('Nav derīga administratora sesija.', 401);
  const key = await crypto.subtle.importKey('raw', new TextEncoder().encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['verify']);
  const sigText = p[1].replace(/-/g, '+').replace(/_/g, '/');
  const sig = Uint8Array.from(atob(sigText + '='.repeat((4 - sigText.length % 4) % 4)), c => c.charCodeAt(0));
  if (!await crypto.subtle.verify('HMAC', key, sig, new TextEncoder().encode(p[0]))) fail('Administratora sesija nav derīga.', 401);
  const raw = p[0].replace(/-/g, '+').replace(/_/g, '/');
  const payload = JSON.parse(atob(raw + '='.repeat((4 - raw.length % 4) % 4)));
  if (!payload.exp || payload.exp < Math.floor(Date.now() / 1000)) fail('Administratora sesijai beidzies derīguma termiņš.', 401);
  return payload;
}
async function requireAdmin(request, env) {
  requireConfig(env, ['SESSION_SECRET', 'ADMIN_EMAIL']);
  const h = request.headers.get('Authorization') || '';
  const session = await verifySession(h.startsWith('Bearer ') ? h.slice(7) : '', env.SESSION_SECRET);
  if (String(session.email).toLowerCase() !== String(env.ADMIN_EMAIL).toLowerCase()) fail('Šim Google kontam nav administratora tiesību.', 403);
  return session;
}
async function googleStart(env) {
  requireConfig(env, ['GOOGLE_CLIENT_ID', 'GOOGLE_REDIRECT_URI', 'ADMIN_EMAIL', 'TOKENS']);
  const state = randomHex(); await saveState(env, state, { provider: 'google' });
  const u = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  u.search = new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, redirect_uri: env.GOOGLE_REDIRECT_URI, response_type: 'code', scope: GOOGLE_SCOPES, access_type: 'offline', prompt: 'consent', include_granted_scopes: 'true', state }).toString();
  return redirect(u.toString());
}
async function googleCallback(url, env) {
  requireConfig(env, ['GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'GOOGLE_REDIRECT_URI', 'ADMIN_EMAIL', 'SESSION_SECRET', 'TOKENS', 'APP_ORIGIN']);
  if (url.searchParams.get('error')) fail('Google autorizācija atteikta: ' + url.searchParams.get('error'));
  await takeState(env, url.searchParams.get('state'), 'google');
  const t = await tokenRequest('https://oauth2.googleapis.com/token', { code: url.searchParams.get('code'), client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, redirect_uri: env.GOOGLE_REDIRECT_URI, grant_type: 'authorization_code' });
  const r = await fetch('https://openidconnect.googleapis.com/v1/userinfo', { headers: { Authorization: 'Bearer ' + t.access_token } });
  const user = await r.json();
  if (!r.ok || !user.email || !user.email_verified || user.email.trim().toLowerCase() !== env.ADMIN_EMAIL.trim().toLowerCase()) fail('Google konts neatbilst norādītajai administratora e-pasta adresei.', 403);
  t.expires_at = Date.now() + (t.expires_in || 3600) * 1000;
  await env.TOKENS.put('google:tokens', JSON.stringify(t));
  const session = await signSession({ email: user.email, exp: Math.floor(Date.now() / 1000) + SESSION_TTL }, env.SESSION_SECRET);
  const target = new URL(env.APP_ORIGIN); target.hash = 'admin_token=' + encodeURIComponent(session) + '&google_auth=ok';
  return redirect(target.toString());
}
async function spotifyStart(env, origin, allowed) {
  requireConfig(env, ['SPOTIFY_CLIENT_ID', 'SPOTIFY_REDIRECT_URI', 'TOKENS']);
  const state = randomHex(); await saveState(env, state, { provider: 'spotify' });
  const u = new URL('https://accounts.spotify.com/authorize');
  u.search = new URLSearchParams({ client_id: env.SPOTIFY_CLIENT_ID, response_type: 'code', redirect_uri: env.SPOTIFY_REDIRECT_URI, scope: SPOTIFY_SCOPES, state }).toString();
  return json({ ok: true, authorizationUrl: u.toString() }, 200, origin, allowed);
}
async function spotifyCallback(url, env) {
  requireConfig(env, ['SPOTIFY_CLIENT_ID', 'SPOTIFY_CLIENT_SECRET', 'SPOTIFY_REDIRECT_URI', 'TOKENS', 'APP_ORIGIN']);
  if (url.searchParams.get('error')) fail('Spotify autorizācija atteikta: ' + url.searchParams.get('error'));
  await takeState(env, url.searchParams.get('state'), 'spotify');
  const basic = btoa(env.SPOTIFY_CLIENT_ID + ':' + env.SPOTIFY_CLIENT_SECRET);
  const t = await tokenRequest('https://accounts.spotify.com/api/token', { code: url.searchParams.get('code'), redirect_uri: env.SPOTIFY_REDIRECT_URI, grant_type: 'authorization_code' }, { Authorization: 'Basic ' + basic });
  t.expires_at = Date.now() + (t.expires_in || 3600) * 1000;
  await env.TOKENS.put('spotify:tokens', JSON.stringify(t));
  const target = new URL(env.APP_ORIGIN); target.hash = 'spotify_auth=ok'; return redirect(target.toString());
}
async function tokenRequest(endpoint, fields, extra = {}) {
  const r = await fetch(endpoint, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...extra }, body: new URLSearchParams(fields) });
  const data = await r.json(); if (!r.ok) fail('OAuth token apmaiņa neizdevās (' + r.status + '). Pārbaudi OAuth iestatījumus.', 502); return data;
}
async function googleToken(env) {
  const t = await env.TOKENS.get('google:tokens', 'json');
  if (!t?.access_token) fail('Vispirms jāpieslēdz Google / YouTube.', 401);
  if (t.expires_at > Date.now() + 60000) return t.access_token;
  if (!t.refresh_token) fail('Google autorizācija jāatkārto, jo nav atjaunošanas pilnvaras.', 401);
  const n = await tokenRequest('https://oauth2.googleapis.com/token', { client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, refresh_token: t.refresh_token, grant_type: 'refresh_token' });
  const next = { ...t, ...n, refresh_token: n.refresh_token || t.refresh_token, expires_at: Date.now() + (n.expires_in || 3600) * 1000 };
  await env.TOKENS.put('google:tokens', JSON.stringify(next)); return next.access_token;
}
async function spotifyToken(env) {
  const t = await env.TOKENS.get('spotify:tokens', 'json'); if (!t?.access_token) fail('Vispirms jāpieslēdz Spotify.', 401);
  if (t.expires_at > Date.now() + 60000) return t.access_token;
  if (!t.refresh_token) fail('Spotify autorizācija jāatkārto.', 401);
  const basic = btoa(env.SPOTIFY_CLIENT_ID + ':' + env.SPOTIFY_CLIENT_SECRET);
  const n = await tokenRequest('https://accounts.spotify.com/api/token', { grant_type: 'refresh_token', refresh_token: t.refresh_token }, { Authorization: 'Basic ' + basic });
  const next = { ...t, ...n, refresh_token: n.refresh_token || t.refresh_token, expires_at: Date.now() + (n.expires_in || 3600) * 1000 };
  await env.TOKENS.put('spotify:tokens', JSON.stringify(next)); return next.access_token;
}
async function ensureSpotifyPlaylist(env) {
  let id = await env.TOKENS.get('playlist:spotify'); if (id) return id;
  const token = await spotifyToken(env);
  const r = await fetch('https://api.spotify.com/v1/me/playlists', { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify({ name: 'Mana Spotify izlase', description: 'Mana dziesmu grāmata — automātiski papildināta izlase.', public: true }) });
  const d = await r.json(); if (!r.ok) fail('Spotify playlistes izveide neizdevās (' + r.status + ').', 502);
  await env.TOKENS.put('playlist:spotify', d.id); await env.TOKENS.put('playlist:spotify:url', d.external_urls?.spotify || 'https://open.spotify.com/playlist/' + d.id); return d.id;
}
async function ensureYouTubePlaylist(env, key, urlKey, title, description) {
  let id = await env.TOKENS.get(key); if (id) return id;
  const token = await googleToken(env);
  const r = await fetch('https://www.googleapis.com/youtube/v3/playlists?part=snippet,status', { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify({ snippet: { title, description }, status: { privacyStatus: 'public' } }) });
  const d = await r.json(); if (!r.ok) fail('YouTube playlistes izveide neizdevās (' + r.status + ').', 502);
  await env.TOKENS.put(key, d.id); await env.TOKENS.put(urlKey, 'https://www.youtube.com/playlist?list=' + d.id); return d.id;
}
async function playlistLinks(env) {
  const [spotify, youtube, karaoke] = await Promise.all([env.TOKENS.get('playlist:spotify:url'), env.TOKENS.get('playlist:youtube:url'), env.TOKENS.get('playlist:karaoke:url')]);
  return { spotify, youtube, karaoke };
}
function spotifyTrackId(v) {
  if (!v) return null; const s = String(v).replace(/&amp;/g, '&').trim(); const m = s.match(/^spotify:track:([A-Za-z0-9]+)$/); if (m) return m[1];
  try { const u = new URL(s); if (!/(^|\.)open\.spotify\.com$/i.test(u.hostname)) return null; return u.pathname.match(/^\/track\/([A-Za-z0-9]+)/)?.[1] || null; } catch { return null; }
}
function youtubeVideoId(v) {
  if (!v) return null; try { const u = new URL(String(v).replace(/&amp;/g, '&').trim()); const host = u.hostname.toLowerCase().replace(/^www\./, '');
    if (host === 'youtu.be') return u.pathname.split('/').filter(Boolean)[0] || null;
    if (host.endsWith('youtube.com')) { if (u.searchParams.get('v')) return u.searchParams.get('v'); const p = u.pathname.split('/').filter(Boolean); if (['shorts', 'embed', 'live'].includes(p[0])) return p[1] || null; }
  } catch {} return null;
}
async function spotifyContains(pid, trackId, token) {
  let url = 'https://api.spotify.com/v1/playlists/' + pid + '/items?limit=100&fields=items(item(id)),next'; let pages = 0;
  while (url && pages++ < 100) { const r = await fetch(url, { headers: { Authorization: 'Bearer ' + token } }); const d = await r.json(); if (!r.ok) fail('Neizdevās pārbaudīt Spotify dublikātus (' + r.status + ').', 502); if ((d.items || []).some(x => x.item?.id === trackId)) return true; url = d.next || null; }
  return false;
}
async function addYouTubeVideo(env, key, videoId) {
  const token = await googleToken(env); const pid = await ensureYouTubePlaylist(env, key, key + ':url', key === 'playlist:youtube' ? 'Mana YouTube izlase' : 'Mana karaoke izlase', 'Dziesmas no Mana dziesmu grāmata.');
  const q = new URL('https://www.googleapis.com/youtube/v3/playlistItems'); q.search = new URLSearchParams({ part: 'id', playlistId: pid, videoId, maxResults: '50' }).toString();
  const check = await fetch(q, { headers: { Authorization: 'Bearer ' + token } }); const cd = await check.json(); if (!check.ok) fail('Neizdevās pārbaudīt YouTube dublikātus (' + check.status + ').', 502); if ((cd.items || []).length) return 'already_present';
  const r = await fetch('https://www.googleapis.com/youtube/v3/playlistItems?part=snippet', { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify({ snippet: { playlistId: pid, resourceId: { kind: 'youtube#video', videoId } } }) });
  if (!r.ok) { const d = await r.json(); fail('YouTube pievienošana neizdevās (' + r.status + '): ' + (d.error?.message || 'API kļūda'), 502); } return 'added';
}
async function syncSong(song, env) {
  if (!song || typeof song !== 'object' || !String(song.title || '').trim()) fail('Dziesmai nav nosaukuma.');
  const out = { id: String(song.id || ''), title: String(song.title).trim(), spotify: 'skipped', youtube: 'skipped', karaoke: 'skipped', warnings: [] };
  // Katrs pakalpojums tiek apstrādāts neatkarīgi: vienas platformas kļūda nepārtrauc pārējās.
  if (song.sp) try {
    const track = spotifyTrackId(song.sp); if (!track) throw new Error('Spotify saite nav derīga dziesmas Spotify track saite.');
    const pid = await ensureSpotifyPlaylist(env); const token = await spotifyToken(env);
    if (await spotifyContains(pid, track, token)) out.spotify = 'already_present';
    else { const r = await fetch('https://api.spotify.com/v1/playlists/' + pid + '/items', { method: 'POST', headers: { Authorization: 'Bearer ' + token, 'Content-Type': 'application/json' }, body: JSON.stringify({ uris: ['spotify:track:' + track] }) }); if (!r.ok) throw new Error('Spotify pievienošana neizdevās (' + r.status + ').'); out.spotify = 'added'; }
  } catch (e) { out.warnings.push('Spotify: ' + safeError(e)); }
  if (song.yt) try { const id = youtubeVideoId(song.yt); if (!id) throw new Error('YouTube saite nav derīga video saite.'); out.youtube = await addYouTubeVideo(env, 'playlist:youtube', id); } catch (e) { out.warnings.push('YouTube: ' + safeError(e)); }
  if (song.kr) try { const id = youtubeVideoId(song.kr); if (!id) throw new Error('Karaoke saite nav derīga YouTube video saite.'); out.karaoke = await addYouTubeVideo(env, 'playlist:karaoke', id); } catch (e) { out.warnings.push('Karaoke: ' + safeError(e)); }
  return out;
}
