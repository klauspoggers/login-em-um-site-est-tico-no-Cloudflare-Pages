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

export async function onRequestGet(context) {
    const provider = context.params.provider;
    if (provider !== 'google' && provider !== 'github') return new Response('Not Found', { status: 404 });

    const tx_raw = generateRandom();
    const state_raw = generateRandom();
    const verifier_raw = generateRandom();
    const nonce_raw = provider === 'google' ? generateRandom() : null;

    const id_hash = await sha256(tx_raw);
    const state_hash = await sha256(state_raw);
    const code_challenge = await sha256(verifier_raw);
    const expires_at = Math.floor(Date.now() / 1000) + 600;

    await context.env.DB.prepare(
        `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at) VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(id_hash, provider, state_hash, nonce_raw, verifier_raw, expires_at).run();

    const baseUrl = context.env.PUBLIC_BASE_URL.replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "").replace(/\/$/, '');
    const redirectUri = `${baseUrl}/oauth/callback/${provider}`;
    const clientId = provider === 'google' ? context.env.GOOGLE_CLIENT_ID : context.env.GITHUB_CLIENT_ID;

    const url = new URL(provider === 'google' ? 'https://accounts.google.com/o/oauth2/v2/auth' : 'https://github.com/login/oauth/authorize');
    url.searchParams.set('client_id', clientId);
    url.searchParams.set('redirect_uri', redirectUri);
    url.searchParams.set('response_type', 'code');
    url.searchParams.set('state', state_raw);
    url.searchParams.set('code_challenge', code_challenge);
    url.searchParams.set('code_challenge_method', 'S256');
    
    if (provider === 'google') {
        url.searchParams.set('scope', 'openid email profile');
        url.searchParams.set('nonce', nonce_raw);
    }

    return new Response(null, {
        status: 302,
        headers: {
            'Location': url.toString(),
            'Set-Cookie': `__Host-oauth-tx=${tx_raw}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`,
            'Cache-Control': 'no-store'
        }
    });
}
