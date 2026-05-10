package scanner

import (
	"database/sql"
	"fmt"

	"github.com/lib/pq"
)

// Column representa uma coluna de banco de dados com nome e tipo SQL.
type Column struct {
	Name     string
	DataType string
}

// Inspector inspeciona o schema de um banco PostgreSQL,
// listando tabelas, colunas e amostras de valores.
type Inspector struct {
	db     *sql.DB
	schema string
}

// NewInspector cria um novo Inspector para o schema especificado.
func NewInspector(db *sql.DB, schema string) *Inspector {
	return &Inspector{db: db, schema: schema}
}

// GetTables retorna os nomes de todas as tabelas do schema configurado.
func (i *Inspector) GetTables() ([]string, error) {
	query := `SELECT table_name FROM information_schema.tables
		WHERE table_schema = $1 AND table_type = 'BASE TABLE'
		ORDER BY table_name`
	rows, err := i.db.Query(query, i.schema)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar tabelas: %w", err)
	}
	defer rows.Close()

	var tables []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, fmt.Errorf("falha ao ler nome da tabela: %w", err)
		}
		tables = append(tables, name)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("erro ao percorrer tabelas: %w", err)
	}
	return tables, nil
}

// GetColumns retorna as colunas de uma tabela com seus tipos SQL.
func (i *Inspector) GetColumns(tableName string) ([]Column, error) {
	query := `SELECT column_name, data_type FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = $2
		ORDER BY ordinal_position`
	rows, err := i.db.Query(query, i.schema, tableName)
	if err != nil {
		return nil, fmt.Errorf("falha ao listar colunas: %w", err)
	}
	defer rows.Close()

	var columns []Column
	for rows.Next() {
		var col Column
		if err := rows.Scan(&col.Name, &col.DataType); err != nil {
			return nil, fmt.Errorf("falha ao ler coluna: %w", err)
		}
		columns = append(columns, col)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("erro ao percorrer colunas: %w", err)
	}
	if len(columns) == 0 {
		return nil, fmt.Errorf("tabela %q não encontrada no schema %q", tableName, i.schema)
	}
	return columns, nil
}

// GetSampleValues retorna até 1000 valores distintos de uma coluna.
// Os identificadores de tabela e coluna são sanitizados com pq.QuoteIdentifier.
func (i *Inspector) GetSampleValues(tableName, columnName string) ([]string, error) {
	query := fmt.Sprintf(
		`SELECT DISTINCT %s::text FROM %s.%s LIMIT 1000`,
		pq.QuoteIdentifier(columnName),
		pq.QuoteIdentifier(i.schema),
		pq.QuoteIdentifier(tableName),
	)
	rows, err := i.db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("falha ao amostrar valores: %w", err)
	}
	defer rows.Close()

	var values []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("falha ao ler valor: %w", err)
		}
		values = append(values, v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("erro ao percorrer valores: %w", err)
	}
	return values, nil
}
