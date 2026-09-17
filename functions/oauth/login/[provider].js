async function generatePKCE() {
    const verifier = crypto.randomUUID() + crypto.randomUUID();
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    const hash = await crypto.subtle.digest('SHA-256', data);
    const challenge = btoa(String.fromCharCode(...new Uint8Array(hash)))
        .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    return { verifier, challenge };
}

export async function onRequest(context) {
    let authUrl = 'Falhou antes de montar';
    let baseUrlStr = '';
    let clientIdStr = '';
    
    try {
        const provider = context.params.provider;

        if (provider !== 'google' && provider !== 'github') {
            return new Response(null, { status: 404 });
        }

        const env = context.env;
        
        // LIMPEZA EXTREMA: Remove espaços, enters (\n, \r), tabs (\t) e caracteres invisíveis
        baseUrlStr = (env.PUBLIC_BASE_URL || "").replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "");
        clientIdStr = provider === 'google' 
            ? (env.GOOGLE_CLIENT_ID || "").replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "") 
            : (env.GITHUB_CLIENT_ID || "").replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "");
        
        const redirectUri = `${baseUrlStr}/oauth/callback/${provider}`;

        const tx = crypto.randomUUID();
        const state = crypto.randomUUID();
        const pkce = await generatePKCE();
        
        const cookieStr = `__Host-oauth-tx=${tx}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;

        if (provider === 'google') {
            const nonce = crypto.randomUUID();
            authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientIdStr}&redirect_uri=${redirectUri}&response_type=code&state=${state}&code_challenge=${pkce.challenge}&code_challenge_method=S256&scope=openid%20email%20profile&nonce=${nonce}`;
        } else {
            authUrl = `https://github.com/login/oauth/authorize?client_id=${clientIdStr}&redirect_uri=${redirectUri}&response_type=code&state=${state}&code_challenge=${pkce.challenge}&code_challenge_method=S256`;
        }

        return new Response(null, {
            status: 302,
            headers: {
                'Location': authUrl,
                'Set-Cookie': cookieStr
            }
        });
    } catch (error) {
        // Se ainda falhar, agora ele vai nos mostrar exatamente qual variável está corrompida!
        return new Response(`Opa, achamos o bug!\nErro: ${error.message}\n--- DADOS ---\nBase URL: [${baseUrlStr}]\nClient ID: [${clientIdStr}]\nURL Final: ${authUrl}`, { status: 500 });
    }
}
