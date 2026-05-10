// Package models define as estruturas de dados do domínio do PII Hunter.
// Todos os tipos aqui representam conceitos do negócio: achados de PII,
// níveis de risco e resultados de scan.
package models

import "time"

// PIIType representa um tipo de dado pessoal conforme definido pela LGPD.
type PIIType string

const (
	PIITypeCPF        PIIType = "CPF"
	PIITypeCNPJ       PIIType = "CNPJ"
	PIITypeEmail      PIIType = "Email"
	PIITypePhone      PIIType = "Telefone"
	PIITypeCreditCard PIIType = "Cartão de Crédito"
	PIITypeCEP        PIIType = "CEP"
	PIITypeBirthDate  PIIType = "Data de Nascimento"
	PIITypeName       PIIType = "Nome"
	PIITypeAddress    PIIType = "Endereço"
)

// RiskLevel representa o nível de risco LGPD de um dado pessoal.
type RiskLevel string

const (
	RiskCritical RiskLevel = "CRÍTICO"
	RiskHigh     RiskLevel = "ALTO"
	RiskMedium   RiskLevel = "MÉDIO"
	RiskLow      RiskLevel = "BAIXO"
)

// DetectionMethod indica como o PII foi detectado.
type DetectionMethod string

const (
	DetectionRegex     DetectionMethod = "regex"
	DetectionHeuristic DetectionMethod = "heuristica"
	DetectionBoth      DetectionMethod = "ambos"
)

// RiskForPII retorna o nível de risco associado a um tipo de PII.
func RiskForPII(p PIIType) RiskLevel {
	switch p {
	case PIITypeCPF, PIITypeCNPJ, PIITypeCreditCard:
		return RiskCritical
	case PIITypeEmail, PIITypePhone, PIITypeBirthDate:
		return RiskHigh
	case PIITypeName, PIITypeCEP:
		return RiskMedium
	case PIITypeAddress:
		return RiskLow
	default:
		return RiskLow
	}
}

// HighestRisk retorna o maior nível de risco de uma lista de tipos de PII.
func HighestRisk(types []PIIType) RiskLevel {
	highest := RiskLow
	order := map[RiskLevel]int{
		RiskCritical: 4,
		RiskHigh:     3,
		RiskMedium:   2,
		RiskLow:      1,
	}
	for _, t := range types {
		r := RiskForPII(t)
		if order[r] > order[highest] {
			highest = r
		}
	}
	return highest
}

// ColumnFinding representa um achado de PII em uma coluna específica.
type ColumnFinding struct {
	ColumnName      string
	ColumnType      string // tipo SQL da coluna (varchar, text, etc.)
	PIITypes        []PIIType
	RiskLevel       RiskLevel
	DetectionMethod DetectionMethod
	SampleValues    []string // valores anonimizados — nunca dados reais
	MatchCount      int      // quantas linhas tiveram match
}

// TableFinding agrupa todos os achados de PII em uma tabela.
type TableFinding struct {
	TableName    string
	Schema       string
	TotalColumns int
	PIIColumns   []ColumnFinding
	HighestRisk  RiskLevel
}

// RiskSummary consolida a contagem de achados por nível de risco.
type RiskSummary struct {
	Critical int
	High     int
	Medium   int
	Low      int
}

// ScanResult é o resultado completo de um scan de banco de dados.
type ScanResult struct {
	Host         string
	Database     string
	Schema       string
	ScannedAt    time.Time
	DurationSec  float64
	TotalTables  int
	TotalColumns int
	TotalPIICols int
	Tables       []TableFinding
	Summary      RiskSummary
}

// Config representa a configuração de conexão com o banco de dados.
type Config struct {
	Host      string
	Port      int
	Database  string
	User      string
	Password  string
	SSLMode   string
	Schema    string
	OutputDir string
}

// ConnectionString retorna a string de conexão PostgreSQL formatada.
func (c Config) ConnectionString() string {
	return "host=" + c.Host +
		" port=" + itoa(c.Port) +
		" dbname=" + c.Database +
		" user=" + c.User +
		" password=" + c.Password +
		" sslmode=" + c.SSLMode
}

// itoa converte int para string sem importar strconv no pacote de modelos.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	result := ""
	for n > 0 {
		result = string(rune('0'+n%10)) + result
		n /= 10
	}
	return result
}
