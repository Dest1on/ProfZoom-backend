package database

import (
	"database/sql"
	"log"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
)

type PostgresConfig struct {
	DSN             string
	MaxOpenConns    int
	MaxIdleConns    int
	ConnMaxIdle     time.Duration
	ConnMaxLifetime time.Duration
}

func NewPostgres(cfg PostgresConfig) *sql.DB {
	db, err := sql.Open("postgres", cfg.DSN)
	if err != nil {
		log.Fatalf("failed to open postgres: %v", err)
	}

	db.SetMaxOpenConns(cfg.MaxOpenConns)
	db.SetMaxIdleConns(cfg.MaxIdleConns)
	db.SetConnMaxIdleTime(cfg.ConnMaxIdle)
	db.SetConnMaxLifetime(cfg.ConnMaxLifetime)

	deadline := time.Now().Add(30 * time.Second)
	backoff := 500 * time.Millisecond
	for {
		if err := db.Ping(); err == nil {
			break
		} else if time.Now().After(deadline) {
			log.Fatalf("failed to ping postgres: %v", err)
		} else {
			log.Printf("postgres not ready yet: %v", err)
			time.Sleep(backoff)
			if backoff < 5*time.Second {
				backoff *= 2
			}
		}
	}

	return db
}
