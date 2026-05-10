package scanner

import (
	"os"
	"strconv"
	"testing"

	"github.com/piihunter/pii-hunter/models"
	"github.com/stretchr/testify/assert"
)

// NOTA: Os testes de conexão real requerem um banco PostgreSQL rodando.
// Para CI/CD, use Docker Compose com um PostgreSQL de teste.
// Os testes marcados com t.Skip rodam apenas quando a variável de ambiente
// PII_HUNTER_TEST_DB está configurada.

func TestConnect_InvalidHost(t *testing.T) {
	t.Run("retorna erro com host inválido", func(t *testing.T) {
		cfg := models.Config{
			Host:     "host-que-nao-existe.local",
			Port:     5432,
			Database: "qualquer",
			User:     "qualquer",
			Password: "qualquer",
			SSLMode:  "disable",
		}
		_, err := Connect(cfg)
		assert.Error(t, err, "deveria retornar erro para host inválido")
	})
}

func TestConnect_ValidConfig(t *testing.T) {
	if testDBNotAvailable() {
		t.Skip("banco de teste não disponível — configure PII_HUNTER_TEST_DB")
	}
	t.Run("conecta com credenciais válidas", func(t *testing.T) {
		cfg := testConfig()
		db, err := Connect(cfg)
		assert.NoError(t, err)
		assert.NotNil(t, db)
		defer db.Close()
	})
}

func TestConnect_InvalidCredentials(t *testing.T) {
	if testDBNotAvailable() {
		t.Skip("banco de teste não disponível — configure PII_HUNTER_TEST_DB")
	}
	t.Run("retorna erro com senha errada", func(t *testing.T) {
		cfg := testConfig()
		cfg.Password = "senha-errada-123"
		_, err := Connect(cfg)
		assert.Error(t, err)
	})
}

// testDBNotAvailable verifica se o banco de testes está disponível.
func testDBNotAvailable() bool {
	return os.Getenv("PII_HUNTER_TEST_DB") == ""
}

// testConfig retorna uma configuração de teste a partir de variáveis de ambiente.
func testConfig() models.Config {
	cfg := models.Config{
		Host:     envOr("PII_HUNTER_TEST_HOST", "localhost"),
		Port:     envOrInt("PII_HUNTER_TEST_PORT", 5432),
		Database: envOr("PII_HUNTER_TEST_DB", "pii_hunter_test"),
		User:     envOr("PII_HUNTER_TEST_USER", "postgres"),
		Password: envOr("PII_HUNTER_TEST_PASSWORD", "postgres"),
		SSLMode:  envOr("PII_HUNTER_TEST_SSLMODE", "disable"),
		Schema:   envOr("PII_HUNTER_TEST_SCHEMA", "public"),
	}
	return cfg
}

func envOr(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func envOrInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return defaultVal
}
