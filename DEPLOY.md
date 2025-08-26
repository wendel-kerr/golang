# Documentação de Deploy - API Vault

## Pré-requisitos
- Docker e Docker Compose instalados
- Go 1.20+ instalado (opcional, para builds locais)
- Banco de dados PostgreSQL (pode ser via Docker)
- Variáveis de ambiente configuradas (.env ou export)

## Passo a Passo

### 1. Clonar o repositório
```bash
git clone <URL_DO_REPOSITORIO>
cd <nome_do_projeto>
```

### 2. Configurar variáveis de ambiente
Crie um arquivo `.env` na raiz do projeto com:
```
DATABASE_URL=postgres://usuario:senha@localhost:5432/dbname?sslmode=disable
DATA_ENCRYPTION_KEY=12345678901234567890123456789012
JWT_SECRET=uma_senha_secreta_para_jwt
BCRYPT_COST=10
```

### 3. Subir o banco de dados com Docker Compose
```bash
docker-compose -f docker-compose-app.yml up -d db
```

### 4. Build e execução da API (Docker)
```bash
docker-compose -f docker-compose-app.yml up --build api
```

### 5. Build e execução local (Go)
```bash
go build -o api-vault ./cmd/api
./api-vault
```

### 6. Migração automática
A API executa `AutoMigrate` ao iniciar, criando as tabelas necessárias.

### 7. Acessar a API
- Endpoints principais: `http://localhost:8080`
- Documentação Swagger: `http://localhost:8080/swagger/index.html`

### 8. Testes
```bash
go test ./tests/...
```

## Observações
- Para produção, configure variáveis de ambiente seguras.
- Use volumes Docker para persistência do banco.
- Para HTTPS, utilize proxy reverso (ex: Nginx, Traefik).
- Rotacione chaves e segredos periodicamente.

## Troubleshooting
- Erros de conexão: verifique `DATABASE_URL` e status do container db.
- Erros de criptografia: garanta que `DATA_ENCRYPTION_KEY` tem 32 bytes.
- Erros JWT: revise `JWT_SECRET`.

## Atualização
- Para atualizar, basta novo build e restart dos containers.

---
Dúvidas? Consulte a documentação Swagger ou abra uma issue.
