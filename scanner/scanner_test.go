package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestScan_ReturnsResult(t *testing.T) {
	if testDBNotAvailable() {
		t.Skip("banco de teste não disponível — configure PII_HUNTER_TEST_DB")
	}
	db, err := Connect(testConfig())
	require.NoError(t, err)
	defer db.Close()

	s := NewScanner(db, testConfig())
	result, err := s.Scan()

	t.Run("sem erro", func(t *testing.T) {
		assert.NoError(t, err)
	})
	t.Run("total de tabelas preenchido", func(t *testing.T) {
		assert.Greater(t, result.TotalTables, 0)
	})
	t.Run("duration preenchida", func(t *testing.T) {
		assert.Greater(t, result.DurationSec, 0.0)
	})
	t.Run("host e banco preenchidos", func(t *testing.T) {
		assert.NotEmpty(t, result.Host)
		assert.NotEmpty(t, result.Database)
	})
}

func TestScan_DetectsPII(t *testing.T) {
	if testDBNotAvailable() {
		t.Skip("banco de teste não disponível — configure PII_HUNTER_TEST_DB")
	}
	db, _ := Connect(testConfig())
	defer db.Close()

	result, err := NewScanner(db, testConfig()).Scan()
	require.NoError(t, err)

	t.Run("detecta PII na tabela usuarios", func(t *testing.T) {
		var found bool
		for _, tf := range result.Tables {
			if tf.TableName == "usuarios" {
				found = true
				assert.NotEmpty(t, tf.PIIColumns)
				assert.NotEqual(t, "", string(tf.HighestRisk))
			}
		}
		assert.True(t, found, "tabela usuarios deveria aparecer no resultado")
	})

	t.Run("resumo por risco está preenchido", func(t *testing.T) {
		total := result.Summary.Critical + result.Summary.High + result.Summary.Medium + result.Summary.Low
		assert.Greater(t, total, 0)
	})
}

func TestScan_AnonymizesSamples(t *testing.T) {
	if testDBNotAvailable() {
		t.Skip("banco de teste não disponível — configure PII_HUNTER_TEST_DB")
	}
	db, _ := Connect(testConfig())
	defer db.Close()

	result, err := NewScanner(db, testConfig()).Scan()
	require.NoError(t, err)

	t.Run("nenhuma amostra contém CPF bruto", func(t *testing.T) {
		for _, tf := range result.Tables {
			for _, cf := range tf.PIIColumns {
				for _, sample := range cf.SampleValues {
					assert.NotRegexp(t, `\d{3}\.\d{3}\.\d{3}-\d{2}`, sample,
						"amostra não deveria conter CPF bruto: %s", sample)
				}
			}
		}
	})
}
