package integrations

import (
	"fmt"
	"log"

	"github.com/appleboy/gin-jwt/v2"
	"github.com/gin-gonic/gin"
	"gorm.io/gorm"

	"api-vault/internal/audit"
	"api-vault/internal/crypto"
	"api-vault/internal/middleware"
)

func RegisterRoutes(r *gin.Engine, conn *gorm.DB, mw *jwt.GinJWTMiddleware) {

	// Listar todas as integrações (protegido)
	// @Summary Listar integrações
	// @Description Lista todas as integrações
	// @Tags integrações
	// @Produce json
	// @Success 200 {array} Integration
	// @Failure 500 {object} gin.H
	// @Router /integrations [get]
	r.GET("/integrations", mw.MiddlewareFunc(), func(c *gin.Context) {
		var list []Integration
		if err := conn.Find(&list).Error; err != nil {
			log.Printf("[AUDIT] [FAIL] Listagem integrações | erro=%v", err)
			_ = audit.SaveAuditLog(conn, "", "listagem_integracoes", "FAIL", err.Error())
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		for i := range list {
			secret, err := crypto.Decrypt(list[i].ClientSecret)
			if err == nil {
				list[i].ClientSecret = secret
			}
		}
		log.Printf("[AUDIT] [OK] Listagem integrações | total=%d", len(list))
		_ = audit.SaveAuditLog(conn, "", "listagem_integracoes", "OK", fmt.Sprintf("total=%d", len(list)))
		c.JSON(200, list)
	})

	// Buscar integração por ID (protegido)
	// @Summary Buscar integração por ID
	// @Description Consulta uma integração pelo ID
	// @Tags integrações
	// @Produce json
	// @Param id path int true "ID da integração"
	// @Success 200 {object} Integration
	// @Failure 404,500 {object} gin.H
	// @Router /integrations/{id} [get]
	r.GET("/integrations/:id", mw.MiddlewareFunc(), func(c *gin.Context) {
		var integration Integration
		id := c.Param("id")
		if err := conn.First(&integration, id).Error; err != nil {
			log.Printf("[AUDIT] [FAIL] Consulta integração por ID | id=%s | erro=%v", id, err)
			_ = audit.SaveAuditLog(conn, "", "consulta_integracao_id", "FAIL", fmt.Sprintf("id=%s erro=%v", id, err))
			c.JSON(404, gin.H{"error": "Integration not found"})
			return
		}
		secret, err := crypto.Decrypt(integration.ClientSecret)
		if err == nil {
			integration.ClientSecret = secret
		}
		log.Printf("[AUDIT] [OK] Consulta integração por ID | id=%s", id)
		_ = audit.SaveAuditLog(conn, "", "consulta_integracao_id", "OK", fmt.Sprintf("id=%s", id))
		c.JSON(200, integration)
	})

	// Atualizar integração (protegido)
	// @Summary Atualizar integração
	// @Description Atualiza uma integração existente
	// @Tags integrações
	// @Accept json
	// @Produce json
	// @Param id path int true "ID da integração"
	// @Param integration body Integration true "Dados da integração"
	// @Success 200 {object} Integration
	// @Failure 400,404,500 {object} gin.H
	// @Router /integrations/{id} [put]
	r.PUT("/integrations/:id", mw.MiddlewareFunc(), func(c *gin.Context) {
		var integration Integration
		id := c.Param("id")
		if err := conn.First(&integration, id).Error; err != nil {
			log.Printf("Erro ao buscar integração para atualizar: %v\n", err)
			c.JSON(404, gin.H{"error": "Integration not found"})
			return
		}
		var input Integration
		if err := c.ShouldBindJSON(&input); err != nil {
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		encryptedSecret, err := crypto.Encrypt(input.ClientSecret)
		if err != nil {
			c.JSON(500, gin.H{"error": "Erro ao criptografar ClientSecret"})
			return
		}
		integration.Name = input.Name
		integration.AuthType = input.AuthType
		integration.ClientID = input.ClientID
		integration.ClientSecret = encryptedSecret
		integration.TokenURL = input.TokenURL
		if err := conn.Save(&integration).Error; err != nil {
			log.Printf("[AUDIT] [FAIL] Atualização integração | id=%s | erro=%v", id, err)
			_ = audit.SaveAuditLog(conn, "", "atualizacao_integracao", "FAIL", fmt.Sprintf("id=%s erro=%v", id, err))
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		secret, err := crypto.Decrypt(integration.ClientSecret)
		if err == nil {
			integration.ClientSecret = secret
		}
		log.Printf("[AUDIT] [OK] Atualização integração | id=%s", id)
		_ = audit.SaveAuditLog(conn, "", "atualizacao_integracao", "OK", fmt.Sprintf("id=%s", id))
		c.JSON(200, integration)
	})

	// Deletar integração (protegido)
	// @Summary Deletar integração
	// @Description Remove uma integração
	// @Tags integrações
	// @Param id path int true "ID da integração"
	// @Success 204 {object} nil
	// @Failure 403,500 {object} gin.H
	// @Router /integrations/{id} [delete]
	r.DELETE("/integrations/:id", mw.MiddlewareFunc(), func(c *gin.Context) {
		if !middleware.IsAdmin(c) {
			c.JSON(403, gin.H{"error": "Acesso permitido apenas para admin"})
			return
		}
		id := c.Param("id")
		if err := conn.Delete(&Integration{}, id).Error; err != nil {
			log.Printf("[AUDIT] [FAIL] Deleção integração | id=%s | erro=%v", id, err)
			_ = audit.SaveAuditLog(conn, "", "delecao_integracao", "FAIL", fmt.Sprintf("id=%s erro=%v", id, err))
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		log.Printf("[AUDIT] [OK] Deleção integração | id=%s", id)
		_ = audit.SaveAuditLog(conn, "", "delecao_integracao", "OK", fmt.Sprintf("id=%s", id))
		c.JSON(204, nil)
	})
	// @Summary Testar integrações
	// @Description Endpoint de teste para integrações
	// @Tags integrações
	// @Produce json
	// @Success 200 {array} Integration
	// @Failure 500 {object} gin.H
	// @Router /integrations/test [get]
	r.GET("/integrations/test", func(c *gin.Context) {
		var list []Integration
		if err := conn.Find(&list).Error; err != nil {
			log.Printf("Erro ao consultar integrações: %v\n", err)
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		log.Printf("Retornando %d integrações salvas\n", len(list))
		c.JSON(200, list)
	})

	// @Summary Cadastro de integração
	// @Description Cria uma nova integração
	// @Tags integrações
	// @Accept json
	// @Produce json
	// @Param integration body IntegrationInput true "Dados da integração"
	// @Success 201 {object} Integration
	// @Failure 400,500 {object} gin.H
	// @Router /integrations [post]
	r.POST("/integrations", mw.MiddlewareFunc(), func(c *gin.Context) {
		log.Println("Tentando fazer o bind do JSON recebido...")
		type IntegrationInput struct {
			Name         string `json:"name" binding:"required"`
			AuthType     string `json:"auth_type" binding:"required"`
			ClientID     string `json:"client_id" binding:"required"`
			ClientSecret string `json:"client_secret" binding:"required"`
			TokenURL     string `json:"token_url" binding:"required"`
		}

		var input IntegrationInput
		if err := c.ShouldBindJSON(&input); err != nil {
			log.Printf("Erro no bind do JSON: %v\n", err)
			c.JSON(400, gin.H{"error": err.Error()})
			return
		}
		// Validações extras
		if len(input.Name) < 3 {
			c.JSON(400, gin.H{"error": "Nome da integração deve ter pelo menos 3 caracteres"})
			return
		}
		if input.AuthType != "client_credentials" && input.AuthType != "authorization_code" {
			c.JSON(400, gin.H{"error": "AuthType inválido"})
			return
		}
		if len(input.ClientID) < 3 || len(input.ClientSecret) < 3 {
			c.JSON(400, gin.H{"error": "ClientID e ClientSecret devem ter pelo menos 3 caracteres"})
			return
		}
		if len(input.TokenURL) < 10 || !(input.TokenURL[:4] == "http") {
			c.JSON(400, gin.H{"error": "TokenURL inválida"})
			return
		}

		log.Printf("Bind do JSON realizado com sucesso: %+v\n", input)

		encryptedSecret, err := crypto.Encrypt(input.ClientSecret)
		if err != nil {
			c.JSON(500, gin.H{"error": "Erro ao criptografar ClientSecret"})
			return
		}

		log.Println("Montando struct Integration...")
		integration := Integration{
			Name:         input.Name,
			AuthType:     input.AuthType,
			ClientID:     input.ClientID,
			ClientSecret: encryptedSecret,
			TokenURL:     input.TokenURL,
		}
		log.Printf("Struct Integration montada: %+v\n", integration)

		log.Println("Persistindo Integration no banco...")
		if err := conn.Create(&integration).Error; err != nil {
			log.Printf("[AUDIT] [FAIL] Cadastro integração | name=%s | erro=%v", input.Name, err)
			_ = audit.SaveAuditLog(conn, "", "cadastro_integracao", "FAIL", fmt.Sprintf("name=%s erro=%v", input.Name, err))
			c.JSON(500, gin.H{"error": err.Error()})
			return
		}
		secret, err := crypto.Decrypt(integration.ClientSecret)
		if err == nil {
			integration.ClientSecret = secret
		}
		log.Printf("[AUDIT] [OK] Cadastro integração | name=%s | id=%d", integration.Name, integration.ID)
		_ = audit.SaveAuditLog(conn, "", "cadastro_integracao", "OK", fmt.Sprintf("name=%s id=%d", integration.Name, integration.ID))
		c.JSON(201, integration)
	})
}
