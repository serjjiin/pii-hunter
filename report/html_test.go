package report

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/piihunter/pii-hunter/models"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// scanResultFixture retorna um ScanResult de exemplo para testes.
func scanResultFixture() models.ScanResult {
	return models.ScanResult{
		Host:         "localhost",
		Database:     "testdb",
		Schema:       "public",
		ScannedAt:    time.Date(2026, 5, 10, 10, 0, 0, 0, time.UTC),
		DurationSec:  3.14,
		TotalTables:  2,
		TotalColumns: 10,
		TotalPIICols: 4,
		Tables: []models.TableFinding{
			{
				TableName:    "usuarios",
				Schema:       "public",
				TotalColumns: 6,
				HighestRisk:  models.RiskCritical,
				PIIColumns: []models.ColumnFinding{
					{
						ColumnName:      "cpf",
						ColumnType:      "varchar",
						PIITypes:        []models.PIIType{models.PIITypeCPF},
						RiskLevel:       models.RiskCritical,
						DetectionMethod: models.DetectionBoth,
						SampleValues:    []string{"***.456.789-**"},
						MatchCount:      5,
					},
					{
						ColumnName:      "email",
						ColumnType:      "varchar",
						PIITypes:        []models.PIIType{models.PIITypeEmail},
						RiskLevel:       models.RiskHigh,
						DetectionMethod: models.DetectionRegex,
						SampleValues:    []string{"j***@email.com"},
						MatchCount:      5,
					},
				},
			},
		},
		Summary: models.RiskSummary{
			Critical: 1,
			High:     1,
			Medium:   0,
			Low:      0,
		},
		Warnings: []string{"falha ao amostrar pagamentos.numero_cartao: timeout"},
	}
}

func TestGenerateHTML(t *testing.T) {
	tmpDir := t.TempDir()
	result := scanResultFixture()

	t.Run("gera arquivo HTML sem erro", func(t *testing.T) {
		err := GenerateHTML(result, tmpDir)
		assert.NoError(t, err)
	})

	t.Run("arquivo HTML é criado no diretório correto", func(t *testing.T) {
		GenerateHTML(result, tmpDir)
		_, err := os.Stat(tmpDir + "/relatorio.html")
		assert.NoError(t, err, "arquivo relatorio.html deveria existir")
	})

	t.Run("HTML contém o nome do banco de dados", func(t *testing.T) {
		GenerateHTML(result, tmpDir)
		content, err := os.ReadFile(tmpDir + "/relatorio.html")
		require.NoError(t, err)
		assert.True(t, strings.Contains(string(content), "testdb"))
	})

	t.Run("HTML contém o nome da tabela encontrada", func(t *testing.T) {
		GenerateHTML(result, tmpDir)
		content, err := os.ReadFile(tmpDir + "/relatorio.html")
		require.NoError(t, err)
		assert.True(t, strings.Contains(string(content), "usuarios"))
	})

	t.Run("HTML contém o nível de risco CRÍTICO", func(t *testing.T) {
		GenerateHTML(result, tmpDir)
		content, err := os.ReadFile(tmpDir + "/relatorio.html")
		require.NoError(t, err)
		assert.True(t, strings.Contains(string(content), "CRÍTICO"))
	})

	t.Run("HTML não contém valores de PII não anonimizados", func(t *testing.T) {
		GenerateHTML(result, tmpDir)
		content, err := os.ReadFile(tmpDir + "/relatorio.html")
		require.NoError(t, err)
		assert.False(t, strings.Contains(string(content), "123.456.789-09"))
	})

	t.Run("HTML renderiza warnings quando existem", func(t *testing.T) {
		GenerateHTML(result, tmpDir)
		content, err := os.ReadFile(tmpDir + "/relatorio.html")
		require.NoError(t, err)
		assert.True(t, strings.Contains(string(content), "⚠️ Avisos"))
		assert.True(t, strings.Contains(string(content), "pagamentos.numero_cartao"))
	})
}

func TestGenerateHTML_EmptyResult(t *testing.T) {
	tmpDir := t.TempDir()
	empty := models.ScanResult{
		Host:         "localhost",
		Database:     "testdb",
		Schema:       "public",
		ScannedAt:    time.Now(),
		TotalTables:  4,
		TotalColumns: 20,
		TotalPIICols: 0,
		Tables:       nil,
		Warnings:     nil,
	}

	t.Run("gera HTML mesmo sem PII encontrado", func(t *testing.T) {
		err := GenerateHTML(empty, tmpDir)
		assert.NoError(t, err)
	})

	t.Run("HTML sem PII mostra zero nos badges", func(t *testing.T) {
		GenerateHTML(empty, tmpDir)
		content, err := os.ReadFile(tmpDir + "/relatorio.html")
		require.NoError(t, err)
		assert.True(t, strings.Contains(string(content), "testdb"))
		assert.True(t, strings.Contains(string(content), "0 coluna(s)"),
			"deveria mostrar 0 coluna(s) nos badges")
	})
}
