package audit_test

import (
	"api-vault/internal/audit"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

func TestAuditLogsEndpoint_AdminAccessAndFilters(t *testing.T) {
	gin.SetMode(gin.TestMode)
	// Banco em memória
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	if err != nil {
		t.Fatalf("Erro ao abrir banco em memória: %v", err)
	}
	db.AutoMigrate(&audit.AuditLog{})

	// Insere alguns logs
	_ = audit.SaveAuditLog(db, "admin", "login", "OK", "sucesso")
	_ = audit.SaveAuditLog(db, "admin", "delete_user", "FAIL", "erro X")
	_ = audit.SaveAuditLog(db, "user1", "login", "OK", "sucesso")

	r := gin.New()
	r.Use(func(c *gin.Context) {
		c.Set("role", "admin") // Simula admin
		c.Next()
	})
	audit.RegisterRoutes(r, db)

	// Testa filtro por usuário
	req, _ := http.NewRequest("GET", "/audit-logs?user=admin", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("Status esperado 200, obtido %d", w.Code)
	}
	var logs []audit.AuditLog
	if err := json.Unmarshal(w.Body.Bytes(), &logs); err != nil {
		t.Fatalf("Erro ao decodificar resposta: %v", err)
	}
	if len(logs) != 2 {
		t.Errorf("Esperado 2 logs para admin, obtido %d", len(logs))
	}

	// Testa filtro por ação
	req2, _ := http.NewRequest("GET", "/audit-logs?action=delete_user", nil)
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	var logs2 []audit.AuditLog
	_ = json.Unmarshal(w2.Body.Bytes(), &logs2)
	if len(logs2) != 1 || logs2[0].Action != "delete_user" {
		t.Errorf("Filtro por ação falhou")
	}

	// Testa acesso negado para não-admin
	r2 := gin.New()
	r2.Use(func(c *gin.Context) {
		c.Set("role", "user") // Simula não-admin
		c.Next()
	})
	audit.RegisterRoutes(r2, db)
	req3, _ := http.NewRequest("GET", "/audit-logs", nil)
	w3 := httptest.NewRecorder()
	r2.ServeHTTP(w3, req3)
	if w3.Code != http.StatusForbidden {
		t.Errorf("Acesso não-admin deveria ser proibido, obtido %d", w3.Code)
	}
}
