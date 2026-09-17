export async function onRequest(context) {
    try {
        const cookieHeader = context.request.headers.get('Cookie') || '';
        const sessionMatch = cookieHeader.match(/__Host-session=([^;]+)/);

        if (!sessionMatch) {
            return new Response(JSON.stringify({ error: "Não autenticado. Faça login primeiro." }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const sessionId = sessionMatch[1];
        const env = context.env;

        const session = await env.DB.prepare(
            `SELECT * FROM sessions WHERE id = ?`
        ).bind(sessionId).first();

        if (!session) {
            return new Response(JSON.stringify({ error: "Sessão inválida ou expirada." }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }
        return new Response(JSON.stringify({
            mensagem: "Login bem-sucedido!",
            provedor: session.provider,
            email: session.email
        }), {
            status: 200,
            headers: { 'Content-Type': 'application/json' }
        });

    } catch (error) {
        return new Response(JSON.stringify({ error: "Erro na API", detalhes: error.message }), { status: 500 });
    }
}
