package report

import (
	"os"
	"testing"

	"github.com/piihunter/pii-hunter/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePDF(t *testing.T) {
	tmpDir := t.TempDir()
	result := scanResultFixture()

	t.Run("gera arquivo PDF sem erro", func(t *testing.T) {
		err := GeneratePDF(result, tmpDir)
		assert.NoError(t, err)
	})

	t.Run("arquivo PDF é criado no diretório correto", func(t *testing.T) {
		GeneratePDF(result, tmpDir)
		_, err := os.Stat(tmpDir + "/relatorio.pdf")
		assert.NoError(t, err, "arquivo relatorio.pdf deveria existir")
	})

	t.Run("PDF não está vazio", func(t *testing.T) {
		GeneratePDF(result, tmpDir)
		info, err := os.Stat(tmpDir + "/relatorio.pdf")
		require.NoError(t, err)
		assert.Greater(t, info.Size(), int64(0), "arquivo PDF não deveria estar vazio")
	})

	t.Run("PDF começa com assinatura PDF", func(t *testing.T) {
		GeneratePDF(result, tmpDir)
		data, err := os.ReadFile(tmpDir + "/relatorio.pdf")
		require.NoError(t, err)
		assert.True(t, len(data) >= 5 && string(data[:5]) == "%PDF-",
			"arquivo deveria começar com assinatura PDF")
	})
}

func TestGeneratePDF_EmptyResult(t *testing.T) {
	tmpDir := t.TempDir()
	empty := models.ScanResult{
		Host:         "localhost",
		Database:     "testdb",
		Schema:       "public",
		ScannedAt:    scanResultFixture().ScannedAt,
		TotalTables:  4,
		TotalColumns: 20,
		TotalPIICols: 0,
		Tables:       nil,
		Warnings:     nil,
	}

	t.Run("gera PDF mesmo sem PII encontrado", func(t *testing.T) {
		err := GeneratePDF(empty, tmpDir)
		assert.NoError(t, err)
	})

	t.Run("PDF sem PII é válido e não vazio", func(t *testing.T) {
		GeneratePDF(empty, tmpDir)
		info, err := os.Stat(tmpDir + "/relatorio.pdf")
		require.NoError(t, err)
		assert.Greater(t, info.Size(), int64(0))
	})
}
