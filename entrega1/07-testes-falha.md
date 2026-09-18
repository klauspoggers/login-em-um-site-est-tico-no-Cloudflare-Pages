# Relatório de Testes de Falha

## Caso 1: Acesso direto à rota de callback sem transação
* **Ação:** Acessar a URL `/oauth/callback/google` diretamente no navegador sem iniciar o fluxo de login (sem o cookie temporário `__Host-oauth-tx`).
* **Resultado Esperado:** O sistema deve bloquear a requisição.
* **Resultado Obtido:** O sistema retornou erro HTTP 400 com a mensagem "Erro: Cookie de transação sumiu!".

## Caso 2: Provedor inválido
* **Ação:** Acessar a URL `/oauth/login/facebook` (provedor não implementado).
* **Resultado Esperado:** O sistema não deve prosseguir com a geração de chaves.
* **Resultado Obtido:** O sistema retornou erro HTTP 404 (Not Found).

## Caso 3: Interceptação e alteração do parâmetro State
* **Ação:** Durante o retorno do Google, alterar manualmente o parâmetro `state` na URL antes de enviar para a rota de callback.
* **Resultado Esperado:** O sistema deve detectar a divergência com o banco de dados e bloquear por suspeita de falsificação (CSRF).
* **Resultado Obtido:** O sistema interceptou a falha e retornou "Erro: State inválido (Tentativa de invasão detectada)".
