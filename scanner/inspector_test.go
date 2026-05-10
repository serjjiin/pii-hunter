package scanner

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetTables(t *testing.T) {
	if testDBNotAvailable() {
		t.Skip("banco de teste não disponível — configure PII_HUNTER_TEST_DB")
	}

	db, err := Connect(testConfig())
	if err != nil {
		t.Fatalf("falha ao conectar para teste: %v", err)
	}
	defer db.Close()

	inspector := NewInspector(db, "public")

	t.Run("retorna lista não vazia de tabelas", func(t *testing.T) {
		tables, err := inspector.GetTables()
		assert.NoError(t, err)
		assert.NotEmpty(t, tables, "deveria ter ao menos uma tabela no schema public")
	})

	t.Run("inclui tabela 'usuarios' do seed", func(t *testing.T) {
		tables, err := inspector.GetTables()
		assert.NoError(t, err)
		assert.Contains(t, tables, "usuarios")
	})
}

func TestGetColumns(t *testing.T) {
	if testDBNotAvailable() {
		t.Skip("banco de teste não disponível — configure PII_HUNTER_TEST_DB")
	}

	db, _ := Connect(testConfig())
	defer db.Close()

	inspector := NewInspector(db, "public")

	t.Run("retorna colunas da tabela usuarios", func(t *testing.T) {
		cols, err := inspector.GetColumns("usuarios")
		assert.NoError(t, err)
		assert.NotEmpty(t, cols)
	})

	t.Run("retorna erro para tabela inexistente", func(t *testing.T) {
		_, err := inspector.GetColumns("tabela_que_nao_existe_xyz")
		assert.Error(t, err)
	})
}

func TestGetSampleValues(t *testing.T) {
	if testDBNotAvailable() {
		t.Skip("banco de teste não disponível — configure PII_HUNTER_TEST_DB")
	}

	db, _ := Connect(testConfig())
	defer db.Close()

	inspector := NewInspector(db, "public")

	t.Run("retorna até 1000 amostras por coluna", func(t *testing.T) {
		samples, err := inspector.GetSampleValues("usuarios", "email")
		assert.NoError(t, err)
		assert.LessOrEqual(t, len(samples), 1000)
	})
}
