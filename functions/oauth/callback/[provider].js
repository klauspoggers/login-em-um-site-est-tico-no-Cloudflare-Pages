function encodeBase64Url(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function generateRandom() {
    const arr = new Uint8Array(32);
    crypto.getRandomValues(arr);
    return encodeBase64Url(arr);
}

async function sha256(text) {
    const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return encodeBase64Url(buffer);
}

function base64UrlToBuffer(b64url) {
    const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64 + '='.repeat((4 - b64.length % 4) % 4));
    const arr = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) arr[i] = bin.charCodeAt(i);
    return arr.buffer;
}

export async function onRequestGet(context) {
    const provider = context.params.provider;
    if (provider !== 'google' && provider !== 'github') return new Response('Not Found', { status: 404 });

    const requestUrl = new URL(context.request.url);
    const code = requestUrl.searchParams.get('code');
    const state = requestUrl.searchParams.get('state');
    const error = requestUrl.searchParams.get('error');

    if (error || !code || !state) return new Response('Erro: Resposta inválida do provedor.', { status: 400, headers: { 'Cache-Control': 'no-store' } });

    const cookieHeader = context.request.headers.get('Cookie') || '';
    const match = cookieHeader.match(/__Host-oauth-tx=([^;]+)/);
    if (!match) return new Response('Erro: Cookie de transação sumiu!', { status: 400, headers: { 'Cache-Control': 'no-store' } });

    const tx_raw = match[1];
    const id_hash = await sha256(tx_raw);
    const now = Math.floor(Date.now() / 1000);

    const tx = await context.env.DB.prepare(`SELECT * FROM oauth_transactions WHERE id_hash = ?`).bind(id_hash).first();
    await context.env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`).bind(id_hash).run();

    if (!tx || tx.expires_at < now) return new Response('Erro: Transação ausente ou expirada.', { status: 400, headers: { 'Cache-Control': 'no-store' } });

    const state_hash = await sha256(state);
    if (tx.state_hash !== state_hash) return new Response('Erro: State inválido (Tentativa de invasão detectada)', { status: 400, headers: { 'Cache-Control': 'no-store' } });

    const baseUrl = context.env.PUBLIC_BASE_URL.replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "").replace(/\/$/, '');
    const redirectUri = `${baseUrl}/oauth/callback/${provider}`;
    const clientId = provider === 'google' ? context.env.GOOGLE_CLIENT_ID : context.env.GITHUB_CLIENT_ID;
    const clientSecret = provider === 'google' ? context.env.GOOGLE_CLIENT_SECRET : context.env.GITHUB_CLIENT_SECRET;

    const tokenUrl = provider === 'google' ? 'https://oauth2.googleapis.com/token' : 'https://github.com/login/oauth/access_token';
    const tokenBody = new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        code: code,
        grant_type: 'authorization_code',
        redirect_uri: redirectUri,
        code_verifier: tx.code_verifier
    });

    const tokenResponse = await fetch(tokenUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
        body: tokenBody.toString()
    });
    
   if (!tokenResponse.ok) return new Response('Erro na troca de código por token.', { status: 400, headers: { 'Cache-Control': 'no-store' } });
    const tokenData = await tokenResponse.json();

    let issuer, subject, email, displayName;

    if (provider === 'google') {
        const idToken = tokenData.id_token;
        if (!idToken) return new Response('Erro: id_token ausente.', { status: 400 });
        
        const parts = idToken.split('.');
        if (parts.length !== 3) return new Response('Erro: JWT malformado.', { status: 400 });
        
        const header = JSON.parse(new TextDecoder().decode(base64UrlToBuffer(parts[0])));
        const payload = JSON.parse(new TextDecoder().decode(base64UrlToBuffer(parts[1])));
        
        if (header.alg !== 'RS256') return new Response('Erro: Algoritmo JWT inválido.', { status: 400 });

        if (!['https://accounts.google.com', 'accounts.google.com'].includes(payload.iss)) return new Response('Erro: Emissor inválido.', { status: 400 });
        if (payload.aud !== clientId) return new Response('Erro: Audiência inválida.', { status: 400 });
        if (payload.exp < now) return new Response('Erro: Token expirado.', { status: 400 });
        if (payload.nonce !== tx.nonce) return new Response('Erro: Nonce inválido.', { status: 400 });

        const jwksRes = await fetch('https://www.googleapis.com/oauth2/v3/certs');
        const jwks = await jwksRes.json();
        const jwk = jwks.keys.find(k => k.kid === header.kid);
        if (!jwk) return new Response('Erro: Chave pública não encontrada.', { status: 400 });

        const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
        const isValid = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, base64UrlToBuffer(parts[2]), new TextEncoder().encode(parts[0] + '.' + parts[1]));
        if (!isValid) return new Response('Erro: Assinatura JWT inválida.', { status: 400 });

        issuer = payload.iss;
        subject = payload.sub;
        email = payload.email || '';
        displayName = payload.name || '';
    } else {
        
        const accessToken = tokenData.access_token;
        if (!accessToken || tokenData.token_type.toLowerCase() !== 'bearer') return new Response('Erro: Token de acesso ausente ou inválido.', { status: 400 });

        const userRes = await fetch('https://api.github.com/user', {
            headers: {
                'Authorization': `Bearer ${accessToken}`,
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'Cloudflare-Pages-Auth-Lab'
            }
        });
        
        if (!userRes.ok) return new Response('Erro: Falha ao obter dados do usuário.', { status: 400 });
        const userData = await userRes.json();

        const basicAuth = btoa(`${clientId}:${clientSecret}`);
        await fetch(`https://api.github.com/applications/${clientId}/grant`, {
            method: 'DELETE',
            headers: {
                'Authorization': `Basic ${basicAuth}`,
                'Accept': 'application/vnd.github+json',
                'X-GitHub-Api-Version': '2022-11-28',
                'User-Agent': 'Cloudflare-Pages-Auth-Lab'
            },
            body: JSON.stringify({ access_token: accessToken })
        });

        issuer = 'https://github.com';
        subject = userData.id.toString();
        email = userData.email || '';
        displayName = userData.name || userData.login || '';
    }

    const session_raw = generateRandom();
    const session_hash = await sha256(session_raw);
    const expires_at = now + 28800;

    await context.env.DB.prepare(
        `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
    ).bind(session_hash, issuer, subject, email, displayName, expires_at, now).run();

    const headers = new Headers();
    headers.append('Location', baseUrl + '/');
    headers.append('Set-Cookie', `__Host-session=${session_raw}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`);
    headers.append('Set-Cookie', `__Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`);
    headers.append('Cache-Control', 'no-store');

    return new Response(null, { status: 302, headers });
}

