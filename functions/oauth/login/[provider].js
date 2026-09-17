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
    try {
        const provider = context.params.provider;

        if (provider !== 'google' && provider !== 'github') {
            return new Response(null, { status: 404 });
        }

        const env = context.env;
        const baseUrl = env.PUBLIC_BASE_URL;
        const clientId = provider === 'google' ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;
        const redirectUri = `${baseUrl}/oauth/callback/${provider}`;

        const tx = crypto.randomUUID();
        const state = crypto.randomUUID();
        const pkce = await generatePKCE();
        
        const cookieStr = `__Host-oauth-tx=${tx}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
        let authUrl = '';

        if (provider === 'google') {
            const nonce = crypto.randomUUID();
            authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&state=${state}&code_challenge=${pkce.challenge}&code_challenge_method=S256&scope=openid email profile&nonce=${nonce}`;
        } else {
            authUrl = `https://github.com/login/oauth/authorize?client_id=${clientId}&redirect_uri=${redirectUri}&response_type=code&state=${state}&code_challenge=${pkce.challenge}&code_challenge_method=S256`;
        }

        return new Response(null, {
            status: 302,
            headers: {
                'Location': authUrl,
                'Set-Cookie': cookieStr
            }
        });
    } catch (error) {
        // Se der qualquer erro, devolvemos uma tela com a mensagem exata para consertar!
        return new Response(`Opa, achamos o bug!\nErro: ${error.message}\nLinha: ${error.stack}`, { status: 500 });
    }
}
