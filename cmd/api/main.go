package main

import (
	_ "api-vault/cmd/api/docs"
	"api-vault/internal/db"
	"api-vault/internal/integrations"
	"log"

	"api-vault/internal/auth"
	"api-vault/internal/tokens"

	"github.com/joho/godotenv"

	"api-vault/internal/audit"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
	"gorm.io/gorm"
)

func setupRouter(conn *gorm.DB) *gin.Engine {
	r := gin.Default()
	mw, err := auth.JWTMiddlewareWithDB(conn)
	if err != nil {
		log.Fatal("Erro ao criar middleware JWT:", err)
	}
	integrations.RegisterRoutes(r, conn, mw)
	tokens.RegisterRoutes(r, conn, mw)
	auth.RegisterRoutes(r, conn, mw)
	audit.RegisterRoutes(r, conn)
	// Endpoint Swagger
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	// @Summary Teste Swagger
	// @Description Endpoint de teste mínimo para Swagger
	// @Router /teste-swagger [get]
	r.GET("/teste-swagger", func(c *gin.Context) {
		c.JSON(200, gin.H{"ok": true})
	})
	return r
}

func main() {

	// Carrega variáveis do .env
	_ = godotenv.Load()
	conn, err := db.Init()
	if err != nil {
		log.Fatal("Erro ao inicializar banco:", err)
	}

	r := setupRouter(conn)
	r.Run(":8080")
}
