package auth

import (
	"fmt"
	"log"
	"net/http"

	"github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"api-vault/internal/audit"
	"api-vault/internal/crypto"
	"api-vault/internal/middleware"
)

// Logger customizado para auditoria
var auditLogger = log.Default()

// Permite injetar logger customizado nos testes
func SetAuditLogger(l *log.Logger) {
	auditLogger = l
}

type UserInput struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
	Role     string `json:"role" binding:"required"`
}

func RegisterRoutes(r *gin.Engine, conn *gorm.DB, mw *jwt.GinJWTMiddleware) {
	// Endpoint de login
	r.POST("/login", mw.LoginHandler)

	// Cadastro de usuário (aberto)
	// @Summary Cadastro de usuário
	// @Description Cria um novo usuário
	// @Tags usuários
	// @Accept json
	// @Produce json
	// @Param user body UserInput true "Dados do usuário"
	// @Success 201 {object} User
	// @Failure 400,500 {object} gin.H
	// @Router /users [post]
	r.POST("/users", func(c *gin.Context) {
		var input UserInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Validações extras
		if len(input.Password) < 6 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Senha deve ter pelo menos 6 caracteres"})
			return
		}
		if len(input.Username) < 3 || len(input.Username) > 32 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username inválido"})
			return
		}
		if input.Role != "user" && input.Role != "admin" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Role deve ser 'user' ou 'admin'"})
			return
		}
		hash, err := crypto.HashPassword(input.Password)
		if err != nil {
			c.JSON(500, gin.H{"error": "Erro ao gerar hash da senha"})
			return
		}
		user := User{
			Username: input.Username,
			Password: hash,
			Role:     input.Role,
		}
		if err := conn.Create(&user).Error; err != nil {
			auditLogger.Printf("[AUDIT] [FAIL] Cadastro usuário | username=%s | role=%s | erro=%v", input.Username, input.Role, err)
			_ = audit.SaveAuditLog(conn, input.Username, "cadastro_usuario", "FAIL", err.Error())
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		auditLogger.Printf("[AUDIT] [OK] Cadastro usuário | username=%s | role=%s | id=%d", user.Username, user.Role, user.ID)
		_ = audit.SaveAuditLog(conn, user.Username, "cadastro_usuario", "OK", "id="+fmt.Sprint(user.ID))
		c.JSON(201, user)
	})

	// Listar usuários (protegido)
	r.GET("/users", mw.MiddlewareFunc(), func(c *gin.Context) {
		var list []User
		if err := conn.Find(&list).Error; err != nil {
			auditLogger.Printf("[AUDIT] [FAIL] Listagem usuários | erro=%v", err)
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		auditLogger.Printf("[AUDIT] [OK] Listagem usuários | total=%d", len(list))
		c.JSON(200, list)
	})

	// Deletar usuário (protegido, admin only)
	r.DELETE("/users/:id", mw.MiddlewareFunc(), func(c *gin.Context) {
		// Verifica se o usuário é admin
		if !middleware.IsAdmin(c) {
			c.JSON(http.StatusForbidden, gin.H{"error": "Acesso permitido apenas para admin"})
			return
		}

		id := c.Param("id")
		if err := conn.Delete(&User{}, id).Error; err != nil {
			auditLogger.Printf("[AUDIT] [FAIL] Deleção usuário | id=%s | erro=%v", id, err)
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		auditLogger.Printf("[AUDIT] [OK] Deleção usuário | id=%s", id)
		c.JSON(204, nil)
	})
}
