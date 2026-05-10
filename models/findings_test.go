package models

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRiskForPII(t *testing.T) {
	t.Run("CPF é risco CRÍTICO", func(t *testing.T) {
		assert.Equal(t, RiskCritical, RiskForPII(PIITypeCPF))
	})
	t.Run("CNPJ é risco CRÍTICO", func(t *testing.T) {
		assert.Equal(t, RiskCritical, RiskForPII(PIITypeCNPJ))
	})
	t.Run("Cartão de crédito é risco CRÍTICO", func(t *testing.T) {
		assert.Equal(t, RiskCritical, RiskForPII(PIITypeCreditCard))
	})
	t.Run("Email é risco ALTO", func(t *testing.T) {
		assert.Equal(t, RiskHigh, RiskForPII(PIITypeEmail))
	})
	t.Run("Telefone é risco ALTO", func(t *testing.T) {
		assert.Equal(t, RiskHigh, RiskForPII(PIITypePhone))
	})
	t.Run("Data de nascimento é risco ALTO", func(t *testing.T) {
		assert.Equal(t, RiskHigh, RiskForPII(PIITypeBirthDate))
	})
	t.Run("Nome é risco MÉDIO", func(t *testing.T) {
		assert.Equal(t, RiskMedium, RiskForPII(PIITypeName))
	})
	t.Run("CEP é risco MÉDIO", func(t *testing.T) {
		assert.Equal(t, RiskMedium, RiskForPII(PIITypeCEP))
	})
	t.Run("Endereço é risco BAIXO", func(t *testing.T) {
		assert.Equal(t, RiskLow, RiskForPII(PIITypeAddress))
	})
}

func TestHighestRisk(t *testing.T) {
	t.Run("retorna CRÍTICO quando há CPF na lista", func(t *testing.T) {
		types := []PIIType{PIITypeName, PIITypeEmail, PIITypeCPF}
		assert.Equal(t, RiskCritical, HighestRisk(types))
	})
	t.Run("retorna ALTO quando não há tipo crítico", func(t *testing.T) {
		types := []PIIType{PIITypeName, PIITypeEmail}
		assert.Equal(t, RiskHigh, HighestRisk(types))
	})
	t.Run("retorna MÉDIO para nome e endereço", func(t *testing.T) {
		types := []PIIType{PIITypeName}
		assert.Equal(t, RiskMedium, HighestRisk(types))
	})
	t.Run("retorna BAIXO para lista com apenas endereço", func(t *testing.T) {
		types := []PIIType{PIITypeAddress}
		assert.Equal(t, RiskLow, HighestRisk(types))
	})
	t.Run("retorna BAIXO para lista vazia", func(t *testing.T) {
		types := []PIIType{}
		assert.Equal(t, RiskLow, HighestRisk(types))
	})
}

func TestConfigConnectionString(t *testing.T) {
	t.Run("gera connection string correta", func(t *testing.T) {
		cfg := Config{
			Host:     "localhost",
			Port:     5432,
			Database: "testdb",
			User:     "paula",
			Password: "senha123",
			SSLMode:  "disable",
		}
		cs := cfg.ConnectionString()
		assert.Contains(t, cs, "host=localhost")
		assert.Contains(t, cs, "port=5432")
		assert.Contains(t, cs, "dbname=testdb")
		assert.Contains(t, cs, "user=paula")
		assert.Contains(t, cs, "sslmode=disable")
	})
}
