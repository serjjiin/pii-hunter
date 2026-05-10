package scanner

import (
	"database/sql"
	"fmt"

	_ "github.com/lib/pq" // driver PostgreSQL
	"github.com/piihunter/pii-hunter/models"
)

// Connect abre e valida uma conexão com o banco PostgreSQL usando as configurações fornecidas.
// Retorna erro descritivo se a conexão falhar ou se o ping não responder.
func Connect(cfg models.Config) (*sql.DB, error) {
	db, err := sql.Open("postgres", cfg.ConnectionString())
	if err != nil {
		return nil, fmt.Errorf("falha ao abrir conexão: %w", err)
	}
	if err := db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("falha ao conectar: %w", err)
	}
	return db, nil
}
