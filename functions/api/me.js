function encodeBase64Url(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function sha256(text) {
    const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return encodeBase64Url(buffer);
}

export async function onRequestGet(context) {
    const cookieHeader = context.request.headers.get('Cookie') || '';
    const match = cookieHeader.match(/__Host-session=([^;]+)/);
    
    if (!match) return new Response('Unauthorized', { status: 401, headers: { 'Cache-Control': 'no-store' } });

    const session_raw = match[1];
    const id_hash = await sha256(session_raw);
    const now = Math.floor(Date.now() / 1000);

    const session = await context.env.DB.prepare(
        `SELECT * FROM sessions WHERE id_hash = ? AND expires_at > ?`
    ).bind(id_hash, now).first();

    if (!session) return new Response('Unauthorized', { status: 401, headers: { 'Cache-Control': 'no-store' } });

    return new Response(JSON.stringify({
        email: session.email,
        displayName: session.display_name || session.email || 'Usuário',
        provedor: session.issuer.includes('google') ? 'google' : 'github'
    }), {
        headers: {
            'Content-Type': 'application/json',
            'Cache-Control': 'no-store'
        }
    });
}
