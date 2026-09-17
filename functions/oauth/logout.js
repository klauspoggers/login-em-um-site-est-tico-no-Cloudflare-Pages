export async function onRequestPost(context) {
    try {
        const cookieHeader = context.request.headers.get('Cookie') || '';
        const sessionMatch = cookieHeader.match(/__Host-session=([^;]+)/);

        if (sessionMatch) {
            const sessionId = sessionMatch[1];
            const env = context.env;
            
            await env.DB.prepare(`DELETE FROM sessions WHERE id = ?`).bind(sessionId).run();
        }

        const deleteCookie = `__Host-session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
        const baseUrlStr = (context.env.PUBLIC_BASE_URL || "").replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "");

        return new Response(null, {
            status: 302,
            headers: {
                'Location': `${baseUrlStr}/`,
                'Set-Cookie': deleteCookie
            }
        });

    } catch (error) {
        return new Response(`Erro ao fazer logout: ${error.message}`, { status: 500 });
    }
}
