package auth_test

import (
	"api-vault/internal/auth"
	"bytes"
	"log"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestAuditLogOnUserCreate(t *testing.T) {
	gin.SetMode(gin.TestMode)
	var buf bytes.Buffer
	logger := log.New(&buf, "", 0)
	auth.SetAuditLogger(logger)

	// Banco em memória para teste
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Erro ao abrir banco em memória: %v", err)
	}
	db.AutoMigrate(&auth.User{})

	r := gin.New()
	// Não precisa de middleware JWT para teste do cadastro
	auth.RegisterRoutes(r, db, nil)

	payload := `{"username":"testuser","password":"testpass123","role":"user"}`
	req := httptest.NewRequest("POST", "/users", bytes.NewBufferString(payload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	logs := buf.String()
	t.Logf("Resposta HTTP: %s", w.Body.String())
	t.Logf("Logs capturados: %s", logs)
	if !containsAuditOK(logs) {
		t.Errorf("Log de auditoria [OK] não encontrado: %s", logs)
	}
}

func containsAuditOK(logs string) bool {
	return bytes.Contains([]byte(logs), []byte("[AUDIT] [OK]"))
}
