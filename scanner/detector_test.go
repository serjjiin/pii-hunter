// Package scanner implementa a lógica de detecção de PII em bancos de dados.
// ATENÇÃO: Este arquivo de testes deve ser escrito ANTES de detector.go (TDD).
package scanner

import (
	"testing"

	"github.com/piihunter/pii-hunter/models"
	"github.com/stretchr/testify/assert"
)

// ============================================================
// Testes de detecção por REGEX (valores)
// ============================================================

func TestDetectCPF(t *testing.T) {
	t.Run("detecta CPF com pontuação", func(t *testing.T) {
		result := DetectValue("123.456.789-09")
		assert.Contains(t, result, models.PIITypeCPF)
	})
	t.Run("detecta CPF sem pontuação", func(t *testing.T) {
		result := DetectValue("12345678909")
		assert.Contains(t, result, models.PIITypeCPF)
	})
	t.Run("detecta CPF no meio de um texto", func(t *testing.T) {
		result := DetectValue("CPF do cliente: 123.456.789-09, obrigado")
		assert.Contains(t, result, models.PIITypeCPF)
	})
	t.Run("ignora sequência de dígitos repetidos (CPF inválido)", func(t *testing.T) {
		result := DetectValue("111.111.111-11")
		assert.NotContains(t, result, models.PIITypeCPF)
	})
	t.Run("ignora texto sem CPF", func(t *testing.T) {
		result := DetectValue("produto sem dados pessoais")
		assert.NotContains(t, result, models.PIITypeCPF)
	})
}

func TestDetectEmail(t *testing.T) {
	t.Run("detecta email simples", func(t *testing.T) {
		result := DetectValue("paula@email.com")
		assert.Contains(t, result, models.PIITypeEmail)
	})
	t.Run("detecta email com subdomínio", func(t *testing.T) {
		result := DetectValue("paula@mail.empresa.com.br")
		assert.Contains(t, result, models.PIITypeEmail)
	})
	t.Run("ignora texto sem @", func(t *testing.T) {
		result := DetectValue("paula em email ponto com")
		assert.NotContains(t, result, models.PIITypeEmail)
	})
}

func TestDetectPhone(t *testing.T) {
	t.Run("detecta telefone com DDD e hífen", func(t *testing.T) {
		result := DetectValue("(61) 99999-9999")
		assert.Contains(t, result, models.PIITypePhone)
	})
	t.Run("detecta telefone com código internacional", func(t *testing.T) {
		result := DetectValue("+5561999999999")
		assert.Contains(t, result, models.PIITypePhone)
	})
	t.Run("ignora número sem DDD", func(t *testing.T) {
		result := DetectValue("9999-9999")
		assert.NotContains(t, result, models.PIITypePhone)
	})
}

func TestDetectCEP(t *testing.T) {
	t.Run("detecta CEP com hífen", func(t *testing.T) {
		result := DetectValue("70040-020")
		assert.Contains(t, result, models.PIITypeCEP)
	})
	t.Run("detecta CEP sem hífen", func(t *testing.T) {
		result := DetectValue("70040020")
		assert.Contains(t, result, models.PIITypeCEP)
	})
}

func TestDetectCreditCard(t *testing.T) {
	t.Run("detecta número Visa", func(t *testing.T) {
		result := DetectValue("4111111111111111")
		assert.Contains(t, result, models.PIITypeCreditCard)
	})
	t.Run("detecta número Mastercard", func(t *testing.T) {
		result := DetectValue("5500000000000004")
		assert.Contains(t, result, models.PIITypeCreditCard)
	})
}

func TestDetectCNPJ(t *testing.T) {
	t.Run("detecta CNPJ com pontuação", func(t *testing.T) {
		result := DetectValue("12.345.678/0001-90")
		assert.Contains(t, result, models.PIITypeCNPJ)
	})
	t.Run("detecta CNPJ sem pontuação", func(t *testing.T) {
		result := DetectValue("12345678000190")
		assert.Contains(t, result, models.PIITypeCNPJ)
	})
}

func TestDetectBirthDate(t *testing.T) {
	t.Run("detecta data no formato YYYY-MM-DD", func(t *testing.T) {
		result := DetectValue("1990-05-15")
		assert.Contains(t, result, models.PIITypeBirthDate)
	})
	t.Run("detecta data no formato DD/MM/YYYY", func(t *testing.T) {
		result := DetectValue("15/05/1990")
		assert.Contains(t, result, models.PIITypeBirthDate)
	})
}

// ============================================================
// Testes de detecção por HEURÍSTICA (nome da coluna)
// ============================================================

func TestDetectByColumnName(t *testing.T) {
	t.Run("detecta 'nome' como PIITypeName", func(t *testing.T) {
		result := DetectByColumnName("nome")
		assert.Contains(t, result, models.PIITypeName)
	})
	t.Run("detecta 'full_name' como PIITypeName", func(t *testing.T) {
		result := DetectByColumnName("full_name")
		assert.Contains(t, result, models.PIITypeName)
	})
	t.Run("detecta 'cpf' como PIITypeCPF", func(t *testing.T) {
		result := DetectByColumnName("cpf")
		assert.Contains(t, result, models.PIITypeCPF)
	})
	t.Run("detecta 'email_address' como PIITypeEmail", func(t *testing.T) {
		result := DetectByColumnName("email_address")
		assert.Contains(t, result, models.PIITypeEmail)
	})
	t.Run("detecta 'celular' como PIITypePhone", func(t *testing.T) {
		result := DetectByColumnName("celular")
		assert.Contains(t, result, models.PIITypePhone)
	})
	t.Run("detecta 'endereco' como PIITypeAddress", func(t *testing.T) {
		result := DetectByColumnName("endereco")
		assert.Contains(t, result, models.PIITypeAddress)
	})
	t.Run("detecta 'logradouro' como PIITypeAddress", func(t *testing.T) {
		result := DetectByColumnName("logradouro")
		assert.Contains(t, result, models.PIITypeAddress)
	})
	t.Run("detecta 'data_nasc' como PIITypeBirthDate", func(t *testing.T) {
		result := DetectByColumnName("data_nasc")
		assert.Contains(t, result, models.PIITypeBirthDate)
	})
	t.Run("é case-insensitive", func(t *testing.T) {
		result := DetectByColumnName("NOME")
		assert.Contains(t, result, models.PIITypeName)
	})
	t.Run("retorna vazio para coluna 'id'", func(t *testing.T) {
		result := DetectByColumnName("id")
		assert.Empty(t, result)
	})
	t.Run("retorna vazio para coluna 'created_at'", func(t *testing.T) {
		result := DetectByColumnName("created_at")
		assert.Empty(t, result)
	})
}

// ============================================================
// Testes de anonimização de valores
// ============================================================

func TestAnonymize(t *testing.T) {
	t.Run("anonimiza CPF mantendo dígitos centrais", func(t *testing.T) {
		result := Anonymize("123.456.789-09", models.PIITypeCPF)
		assert.Equal(t, "***.456.789-**", result)
	})
	t.Run("anonimiza email mantendo domínio", func(t *testing.T) {
		result := Anonymize("paula@email.com", models.PIITypeEmail)
		assert.Contains(t, result, "@email.com")
		assert.Contains(t, result, "*")
	})
	t.Run("anonimiza cartão mantendo últimos 4 dígitos", func(t *testing.T) {
		result := Anonymize("4111111111111111", models.PIITypeCreditCard)
		assert.Contains(t, result, "1111")
		assert.Contains(t, result, "*")
	})
}
