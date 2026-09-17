export async function onRequest(context) {
    let debugPasso = 'Início';
    
    try {
        const provider = context.params.provider;
        if (provider !== 'google' && provider !== 'github') return new Response(null, { status: 404 });

        debugPasso = 'Lendo URL e Cookie';
        const url = new URL(context.request.url);
        const code = url.searchParams.get('code');
        const state = url.searchParams.get('state');
        
        const cookieHeader = context.request.headers.get('Cookie') || '';
        const txMatch = cookieHeader.match(/__Host-oauth-tx=([^;]+)/);
        if (!txMatch) return new Response('Erro: Cookie de transação sumiu!', { status: 400 });
        const tx = txMatch[1];

        debugPasso = 'Preparando Chaves';
        const env = context.env;
        const baseUrlStr = (env.PUBLIC_BASE_URL || "").replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "");
        const redirectUri = `${baseUrlStr}/oauth/callback/${provider}`;
        
        const clientIdStr = provider === 'google' 
            ? (env.GOOGLE_CLIENT_ID || "").replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "") 
            : (env.GITHUB_CLIENT_ID || "").replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "");
            
        const clientSecretStr = provider === 'google'
            ? (env.GOOGLE_CLIENT_SECRET || "").replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "")
            : (env.GITHUB_CLIENT_SECRET || "").replace(/[\r\n\t\s\x00-\x1F\x7F]/g, "");

        debugPasso = 'Consultando Banco D1';
        const dbResult = await env.DB.prepare(
            `SELECT * FROM oauth_transactions WHERE tx = ? AND provider = ?`
        ).bind(tx, provider).first();

        if (!dbResult) return new Response('Erro: Transação não encontrada no banco', { status: 400 });
        if (dbResult.state !== state) return new Response('Erro: State inválido (Tentativa de invasão detectada)', { status: 400 });

        debugPasso = 'Trocando Código por Token';
        let tokenUrl = provider === 'google' ? 'https://oauth2.googleapis.com/token' : 'https://github.com/login/oauth/access_token';
        
        const tokenParams = new URLSearchParams({
            client_id: clientIdStr,
            client_secret: clientSecretStr,
            code: code,
            redirect_uri: redirectUri,
            grant_type: 'authorization_code',
            code_verifier: dbResult.code_verifier
        });

        const tokenResponse = await fetch(tokenUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Accept': 'application/json' },
            body: tokenParams.toString()
        });
        const tokenData = await tokenResponse.json();
        if (tokenData.error) return new Response(`Erro na API do provedor: ${tokenData.error}`, { status: 400 });

        debugPasso = 'Buscando Dados do Usuário';
        let accountId = '';
        let email = '';

        if (provider === 'google') {
            const userResponse = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
                headers: { 'Authorization': `Bearer ${tokenData.access_token}` }
            });
            const userData = await userResponse.json();
            accountId = userData.id;
            email = userData.email;
        } else {
            const userResponse = await fetch('https://api.github.com/user', {
                headers: { 'Authorization': `Bearer ${tokenData.access_token}`, 'User-Agent': 'Cloudflare-Pages-Lab' }
            });
            const userData = await userResponse.json();
            accountId = userData.id.toString();
            email = userData.email || userData.login;
        }

        debugPasso = 'Salvando Sessão no Banco';
        const sessionId = crypto.randomUUID();
        const now = Math.floor(Date.now() / 1000);
        
        await env.DB.prepare(
            `INSERT INTO sessions (id, provider, provider_account_id, email, created_at) VALUES (?, ?, ?, ?, ?)`
        ).bind(sessionId, provider, accountId, email, now).run();

        await env.DB.prepare(`DELETE FROM oauth_transactions WHERE tx = ?`).bind(tx).run();

        debugPasso = 'Redirecionando pra Home';
        const sessionCookie = `__Host-session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`;
        const deleteTxCookie = `__Host-oauth-tx=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;

        return new Response(null, {
            status: 302,
            headers: new Headers([
                ['Location', `${baseUrlStr}/`],
                ['Set-Cookie', sessionCookie],
                ['Set-Cookie', deleteTxCookie]
            ])
        });

    } catch (error) {
        return new Response(`Opa, achamos o bug no Callback!\nPasso atual: ${debugPasso}\nErro: ${error.message}\nLinha: ${error.stack}`, { status: 500 });
    }
}
