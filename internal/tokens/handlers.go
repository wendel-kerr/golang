package tokens

import (
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"api-vault/internal/audit"
	"api-vault/internal/crypto"
	"api-vault/internal/middleware"
)

type TokenInput struct {
	IntegrationID uint      `json:"integration_id" binding:"required"`
	AccessToken   string    `json:"access_token" binding:"required"`
	RefreshToken  string    `json:"refresh_token" binding:"required"`
	ExpiresAt     time.Time `json:"expires_at" binding:"required"`
}

func RegisterRoutes(r *gin.Engine, conn *gorm.DB, mw *jwt.GinJWTMiddleware) {
	// Listar todos os tokens (protegido)
	// @Summary Listar tokens
	// @Description Lista todos os tokens
	// @Tags tokens
	// @Produce json
	// @Success 200 {array} Token
	// @Failure 500 {object} gin.H
	// @Router /tokens [get]
	r.GET("/tokens", mw.MiddlewareFunc(), func(c *gin.Context) {
		var list []Token
		if err := conn.Find(&list).Error; err != nil {
			log.Printf("[AUDIT] [FAIL] Listagem tokens | erro=%v", err)
			_ = audit.SaveAuditLog(conn, "", "listagem_tokens", "FAIL", err.Error())
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		for i := range list {
			access, err := crypto.Decrypt(list[i].AccessToken)
			if err == nil {
				list[i].AccessToken = access
			}
			refresh, err := crypto.Decrypt(list[i].RefreshToken)
			if err == nil {
				list[i].RefreshToken = refresh
			}
		}
		log.Printf("[AUDIT] [OK] Listagem tokens | total=%d", len(list))
		_ = audit.SaveAuditLog(conn, "", "listagem_tokens", "OK", fmt.Sprintf("total=%d", len(list)))
		c.JSON(200, list)
	})

	// Buscar token por ID (protegido)
	// @Summary Buscar token por ID
	// @Description Consulta um token pelo ID
	// @Tags tokens
	// @Produce json
	// @Param id path int true "ID do token"
	// @Success 200 {object} Token
	// @Failure 404,500 {object} gin.H
	// @Router /tokens/{id} [get]
	r.GET("/tokens/:id", mw.MiddlewareFunc(), func(c *gin.Context) {
		var token Token
		id := c.Param("id")
		if err := conn.First(&token, id).Error; err != nil {
			log.Printf("[AUDIT] [FAIL] Consulta token por ID | id=%s | erro=%v", id, err)
			_ = audit.SaveAuditLog(conn, "", "consulta_token_id", "FAIL", fmt.Sprintf("id=%s erro=%v", id, err))
			c.JSON(404, gin.H{"error": "Token not found"})
			return
		}
		access, err := crypto.Decrypt(token.AccessToken)
		if err == nil {
			token.AccessToken = access
		}
		refresh, err := crypto.Decrypt(token.RefreshToken)
		if err == nil {
			token.RefreshToken = refresh
		}
		log.Printf("[AUDIT] [OK] Consulta token por ID | id=%s", id)
		_ = audit.SaveAuditLog(conn, "", "consulta_token_id", "OK", fmt.Sprintf("id=%s", id))
		c.JSON(200, token)
	})

	// Criar token (protegido)
	// @Summary Cadastro de token
	// @Description Cria um novo token
	// @Tags tokens
	// @Accept json
	// @Produce json
	// @Param token body TokenInput true "Dados do token"
	// @Success 201 {object} Token
	// @Failure 400,500 {object} gin.H
	// @Router /tokens [post]
	r.POST("/tokens", mw.MiddlewareFunc(), func(c *gin.Context) {
		var input TokenInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		// Validações extras
		if input.IntegrationID == 0 {
			c.JSON(400, gin.H{"error": "IntegrationID obrigatório"})
			return
		}
		if len(input.AccessToken) < 6 || len(input.RefreshToken) < 6 {
			c.JSON(400, gin.H{"error": "AccessToken e RefreshToken devem ter pelo menos 6 caracteres"})
			return
		}
		if input.ExpiresAt.IsZero() {
			c.JSON(400, gin.H{"error": "ExpiresAt obrigatório e deve ser uma data válida"})
			return
		}
		encryptedAccess, err := crypto.Encrypt(input.AccessToken)
		if err != nil {
			c.JSON(500, gin.H{"error": "Erro ao criptografar AccessToken"})
			return
		}
		encryptedRefresh, err := crypto.Encrypt(input.RefreshToken)
		if err != nil {
			c.JSON(500, gin.H{"error": "Erro ao criptografar RefreshToken"})
			return
		}
		token := Token{
			IntegrationID: input.IntegrationID,
			AccessToken:   encryptedAccess,
			RefreshToken:  encryptedRefresh,
			ExpiresAt:     input.ExpiresAt,
		}
		if err := conn.Create(&token).Error; err != nil {
			log.Printf("[AUDIT] [FAIL] Cadastro token | integration_id=%d | erro=%v", input.IntegrationID, err)
			_ = audit.SaveAuditLog(conn, "", "cadastro_token", "FAIL", fmt.Sprintf("integration_id=%d erro=%v", input.IntegrationID, err))
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		access, err := crypto.Decrypt(token.AccessToken)
		if err == nil {
			token.AccessToken = access
		}
		refresh, err := crypto.Decrypt(token.RefreshToken)
		if err == nil {
			token.RefreshToken = refresh
		}
		log.Printf("[AUDIT] [OK] Cadastro token | id=%d | integration_id=%d", token.ID, token.IntegrationID)
		_ = audit.SaveAuditLog(conn, "", "cadastro_token", "OK", fmt.Sprintf("id=%d integration_id=%d", token.ID, token.IntegrationID))
		c.JSON(201, token)
	})

	// Atualizar token (protegido)
	// @Summary Atualizar token
	// @Description Atualiza um token existente
	// @Tags tokens
	// @Accept json
	// @Produce json
	// @Param id path int true "ID do token"
	// @Param token body TokenInput true "Dados do token"
	// @Success 200 {object} Token
	// @Failure 400,404,500 {object} gin.H
	// @Router /tokens/{id} [put]
	r.PUT("/tokens/:id", mw.MiddlewareFunc(), func(c *gin.Context) {
		var token Token
		id := c.Param("id")
		if err := conn.First(&token, id).Error; err != nil {
			log.Printf("Erro ao buscar token para atualizar: %v\n", err)
			c.JSON(404, gin.H{"error": "Token not found"})
			return
		}
		var input TokenInput
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		encryptedAccess, err := crypto.Encrypt(input.AccessToken)
		if err != nil {
			c.JSON(500, gin.H{"error": "Erro ao criptografar AccessToken"})
			return
		}
		encryptedRefresh, err := crypto.Encrypt(input.RefreshToken)
		if err != nil {
			c.JSON(500, gin.H{"error": "Erro ao criptografar RefreshToken"})
			return
		}
		token.IntegrationID = input.IntegrationID
		token.AccessToken = encryptedAccess
		token.RefreshToken = encryptedRefresh
		token.ExpiresAt = input.ExpiresAt
		if err := conn.Save(&token).Error; err != nil {
			log.Printf("[AUDIT] [FAIL] Atualização token | id=%s | erro=%v", id, err)
			_ = audit.SaveAuditLog(conn, "", "atualizacao_token", "FAIL", fmt.Sprintf("id=%s erro=%v", id, err))
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		access, err := crypto.Decrypt(token.AccessToken)
		if err == nil {
			token.AccessToken = access
		}
		refresh, err := crypto.Decrypt(token.RefreshToken)
		if err == nil {
			token.RefreshToken = refresh
		}
		log.Printf("[AUDIT] [OK] Atualização token | id=%s", id)
		_ = audit.SaveAuditLog(conn, "", "atualizacao_token", "OK", fmt.Sprintf("id=%s", id))
		c.JSON(200, token)
	})

	// Deletar token (protegido)
	// @Summary Deletar token
	// @Description Remove um token
	// @Tags tokens
	// @Param id path int true "ID do token"
	// @Success 204 {object} nil
	// @Failure 403,500 {object} gin.H
	// @Router /tokens/{id} [delete]
	r.DELETE("/tokens/:id", mw.MiddlewareFunc(), func(c *gin.Context) {
		if !middleware.IsAdmin(c) {
			c.JSON(403, gin.H{"error": "Acesso permitido apenas para admin"})
			return
		}
		id := c.Param("id")
		if err := conn.Delete(&Token{}, id).Error; err != nil {
			log.Printf("[AUDIT] [FAIL] Deleção token | id=%s | erro=%v", id, err)
			_ = audit.SaveAuditLog(conn, "", "delecao_token", "FAIL", fmt.Sprintf("id=%s erro=%v", id, err))
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		log.Printf("[AUDIT] [OK] Deleção token | id=%s", id)
		_ = audit.SaveAuditLog(conn, "", "delecao_token", "OK", fmt.Sprintf("id=%s", id))
		c.JSON(204, nil)
	})
}
