package integration_test

import (
	"api-vault/internal/audit"
	"api-vault/internal/auth"
	"api-vault/internal/integrations"
	"api-vault/internal/tokens"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestFullFlow(t *testing.T) {
	// Define chave de criptografia para ambiente de teste
	os.Setenv("DATA_ENCRYPTION_KEY", "12345678901234567890123456789012")
	gin.SetMode(gin.TestMode)
	// Banco em memória
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Erro ao abrir banco em memória: %v", err)
	}
	db.AutoMigrate(&auth.User{}, &integrations.Integration{}, &tokens.Token{}, &audit.AuditLog{})

	r := gin.New()
	// Simula admin
	r.Use(func(c *gin.Context) {
		c.Set("role", "admin")
		c.Next()
	})
	mw, err := auth.JWTMiddlewareWithDB(db)
	if err != nil {
		t.Fatalf("Erro ao criar middleware JWT: %v", err)
	}
	auth.RegisterRoutes(r, db, mw)
	integrations.RegisterRoutes(r, db, mw)
	tokens.RegisterRoutes(r, db, mw)
	audit.RegisterRoutes(r, db)

	// Cadastro de usuário admin
	userPayload := `{"username":"admin","password":"admin123","role":"admin"}`
	req := httptest.NewRequest("POST", "/users", bytes.NewBufferString(userPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("Cadastro de usuário falhou: %d", w.Code)
	}

	// Login para obter token JWT
	loginPayload := `{"username":"admin","password":"admin123"}`
	reqLogin := httptest.NewRequest("POST", "/login", bytes.NewBufferString(loginPayload))
	reqLogin.Header.Set("Content-Type", "application/json")
	wLogin := httptest.NewRecorder()
	r.ServeHTTP(wLogin, reqLogin)
	if wLogin.Code != http.StatusOK {
		t.Fatalf("Login falhou: %d", wLogin.Code)
	}
	var loginResp map[string]interface{}
	_ = json.Unmarshal(wLogin.Body.Bytes(), &loginResp)
	token, ok := loginResp["token"].(string)
	if !ok || token == "" {
		t.Fatalf("Token JWT não retornado no login")
	}

	// Criação de integração
	integrationPayload := `{"name":"TestAPI","auth_type":"client_credentials","client_id":"cid","client_secret":"csecret","token_url":"http://token.url"}`
	req2 := httptest.NewRequest("POST", "/integrations", bytes.NewBufferString(integrationPayload))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Set("Authorization", "Bearer "+token)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusCreated {
		t.Fatalf("Cadastro de integração falhou: %d, body: %s", w2.Code, w2.Body.String())
	}
	var integration integrations.Integration
	_ = json.Unmarshal(w2.Body.Bytes(), &integration)

	// Criação de token
	tokenPayload := `{"integration_id":` + itoa(integration.ID) + `,"access_token":"atoken","refresh_token":"rtoken","expires_at":"2025-12-31T23:59:59Z"}`
	req3 := httptest.NewRequest("POST", "/tokens", bytes.NewBufferString(tokenPayload))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Set("Authorization", "Bearer "+token)
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, req3)
	if w3.Code != http.StatusCreated {
		t.Fatalf("Cadastro de token falhou: %d", w3.Code)
	}

	// Consulta auditoria
	req4 := httptest.NewRequest("GET", "/audit-logs?user=admin", nil)
	req4.Header.Set("Authorization", "Bearer "+token)
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, req4)
	if w4.Code != http.StatusOK {
		t.Fatalf("Consulta de auditoria falhou: %d", w4.Code)
	}
	var logs []audit.AuditLog
	_ = json.Unmarshal(w4.Body.Bytes(), &logs)
	if len(logs) == 0 {
		t.Errorf("Nenhum log de auditoria encontrado")
	}
}

func itoa(i uint) string {
	return fmt.Sprintf("%d", i)
}
