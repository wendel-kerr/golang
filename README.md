# API Vault - Gestão de Tokens de Autenticação

Projeto para centralizar e gerenciar tokens OAuth2 e credenciais de integrações externas.

## Estrutura inicial
- `/cmd/api` — ponto de entrada da API
- `/internal/integrations` — lógica de integrações externas
- `/internal/tokens` — gestão e renovação de tokens
- `/internal/auth` — autenticação JWT
- `/internal/db` — acesso ao banco
- `/internal/crypto` — criptografia
- `/pkg` — utilitários
- `/docs` — documentação

## Como iniciar
1. Instale Go 1.24+
2. Instale Docker e docker-compose
3. Siga os próximos passos para dependências e configuração
