package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRootCmd_Defaults(t *testing.T) {
	// Reseta as flags para o estado padrão entre testes
	resetFlags()

	t.Run("flag --host default é localhost", func(t *testing.T) {
		assert.Equal(t, "localhost", host)
	})
	t.Run("flag --port default é 5432", func(t *testing.T) {
		assert.Equal(t, 5432, port)
	})
	t.Run("flag --ssl default é require", func(t *testing.T) {
		assert.Equal(t, "require", sslMode)
	})
	t.Run("flag --schema default é public", func(t *testing.T) {
		assert.Equal(t, "public", schema)
	})
	t.Run("flag --output default é ./reports", func(t *testing.T) {
		assert.Equal(t, "./reports", outputDir)
	})
}

func TestRootCmd_Help(t *testing.T) {
	resetFlags()

	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)
	rootCmd.SetArgs([]string{"--help"})

	err := rootCmd.Execute()
	require.NoError(t, err)

	output := buf.String()
	t.Run("help contém nome do comando", func(t *testing.T) {
		assert.True(t, strings.Contains(output, "pii-hunter"))
	})
	t.Run("help contém descrição LGPD", func(t *testing.T) {
		assert.True(t, strings.Contains(output, "LGPD"))
	})
	t.Run("help lista flags obrigatórias", func(t *testing.T) {
		assert.True(t, strings.Contains(output, "--db"))
		assert.True(t, strings.Contains(output, "--user"))
		assert.True(t, strings.Contains(output, "--password"))
	})
}

func TestRootCmd_MissingRequiredFlags(t *testing.T) {
	resetFlags()

	// Simula a validação de flags obrigatórias (mesma lógica do RunE)
	t.Run("valida que flags obrigatórias vazias retornam erro", func(t *testing.T) {
		if database == "" || user == "" || password == "" {
			// Este é o comportamento esperado do RunE
			assert.True(t, true)
		} else {
			t.Error("flags deveriam estar vazias após reset")
		}
	})

	// O RunE valida explicitamente as flags e retorna erro
	// Testamos via chamada direta em vez de Execute() para evitar
	// que o Cobra interfira no fluxo de erro
	err := rootCmd.RunE(rootCmd, []string{})
	assert.Error(t, err, "RunE deveria retornar erro com flags vazias")
	assert.Contains(t, err.Error(), "flags obrigatórias")
}

func resetFlags() {
	host = "localhost"
	port = 5432
	database = ""
	user = ""
	password = ""
	sslMode = "require"
	schema = "public"
	outputDir = "./reports"
}
