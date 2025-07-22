package main

import (
	"authorization-task/internal/database"
	"authorization-task/internal/env"
	"database/sql"
	"log"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/file"
	_ "github.com/lib/pq"

	_ "authorization-task/cmd/api/docs"
)

type application struct {
	port          int
	jwtSecret     string
	refreshSecret string
	webHookUrl    string
	repo          database.RefreshModel
}

// @title Authentication Service API
// @version 1.0
// @description REST API для сервиса аутентификации

// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Access

// @host localhost:8080
// @BasePath /
func main() {
	db, err := sql.Open("postgres", os.Getenv("DB_URL"))
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	instance, err := postgres.WithInstance(db, &postgres.Config{})
	if err != nil {
		log.Fatal(err)
	}

	fSrc, err := (&file.File{}).Open("./migrations")
	if err != nil {
		log.Fatal(err)
	}

	m, err := migrate.NewWithInstance("file", fSrc, "postgres", instance)

	if err := m.Up(); err != nil && err != migrate.ErrNoChange {
		log.Fatal(err)
	}

	var repo database.RefreshModel
	repo.DB = db
	app := &application{
		port:          env.GetEnvInt("PORT", 8080),
		jwtSecret:     env.GetEnvString("JWT_SECRET", ""),
		refreshSecret: env.GetEnvString("REFRESH_SECRET", ""),
		webHookUrl:    env.GetEnvString("WEBHOOK_URL", "http://default-webhook"),
		repo:          repo,
	}

	if app.jwtSecret == "" {
		log.Fatal("JWT_SECRET must be set")
	}

	if app.refreshSecret == "" {
		log.Fatal("REFRESH_SECRET must be set")
	}

	if err := app.Serve(); err != nil {
		log.Fatal(err)
	}
}
