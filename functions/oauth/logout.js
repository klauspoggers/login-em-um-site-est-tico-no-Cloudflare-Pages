function encodeBase64Url(buffer) {
    return btoa(String.fromCharCode(...new Uint8Array(buffer))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
async function sha256(text) {
    const buffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return encodeBase64Url(buffer);
}

export async function onRequestPost(context) {
    const origin = context.request.headers.get('Origin') || '';
    const baseUrl = context.env.PUBLIC_BASE_URL.replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "").replace(/\/$/, '');
    
    if (origin !== baseUrl) return new Response('Forbidden', { status: 403, headers: { 'Cache-Control': 'no-store' } });

    const cookieHeader = context.request.headers.get('Cookie') || '';
    const match = cookieHeader.match(/__Host-session=([^;]+)/);
    
    if (match) {
        const id_hash = await sha256(match[1]);
        await context.env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`).bind(id_hash).run();
    }

    return new Response(null, {
        status: 302,
        headers: {
            'Location': '/',
            'Set-Cookie': `__Host-session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`,
            'Cache-Control': 'no-store'
        }
    });
}
