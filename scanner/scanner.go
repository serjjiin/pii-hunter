package scanner

import (
	"database/sql"
	"fmt"
	"time"

	"github.com/piihunter/pii-hunter/models"
)

// Scanner orquestra o scan completo de um banco de dados PostgreSQL.
type Scanner struct {
	db        *sql.DB
	inspector *Inspector
	cfg       models.Config
}

// NewScanner cria um Scanner a partir de uma conexão e configuração existentes.
func NewScanner(db *sql.DB, cfg models.Config) *Scanner {
	return &Scanner{
		db:        db,
		inspector: NewInspector(db, cfg.Schema),
		cfg:       cfg,
	}
}

// Scan executa o scan completo e retorna o ScanResult.
func (s *Scanner) Scan() (models.ScanResult, error) {
	start := time.Now()
	result := models.ScanResult{
		Host:      s.cfg.Host,
		Database:  s.cfg.Database,
		Schema:    s.cfg.Schema,
		ScannedAt: start,
	}

	tables, err := s.inspector.GetTables()
	if err != nil {
		return result, fmt.Errorf("falha ao listar tabelas: %w", err)
	}
	result.TotalTables = len(tables)

	for _, tableName := range tables {
		tf, colCount, err := s.scanTable(tableName)
		if err != nil {
			return result, fmt.Errorf("falha ao escanear %s: %w", tableName, err)
		}
		result.TotalColumns += colCount
		if len(tf.PIIColumns) > 0 {
			result.TotalPIICols += len(tf.PIIColumns)
			result.Tables = append(result.Tables, tf)
		}
	}

	result.DurationSec = time.Since(start).Seconds()
	result.Summary = buildSummary(result.Tables)
	return result, nil
}

func (s *Scanner) scanTable(tableName string) (models.TableFinding, int, error) {
	cols, err := s.inspector.GetColumns(tableName)
	if err != nil {
		return models.TableFinding{}, 0, err
	}

	tf := models.TableFinding{
		TableName:    tableName,
		Schema:       s.cfg.Schema,
		TotalColumns: len(cols),
	}

	for _, col := range cols {
		cf, hasPII := s.scanColumn(tableName, col)
		if hasPII {
			tf.PIIColumns = append(tf.PIIColumns, cf)
		}
	}

	if len(tf.PIIColumns) > 0 {
		tf.HighestRisk = highestRiskFromColumns(tf.PIIColumns)
	}

	return tf, len(cols), nil
}

func (s *Scanner) scanColumn(tableName string, col Column) (models.ColumnFinding, bool) {
	heuristicTypes := DetectByColumnName(col.Name)

	samples, _ := s.inspector.GetSampleValues(tableName, col.Name)
	regexTypes := detectInSamples(samples)

	allTypes := mergeTypes(heuristicTypes, regexTypes)
	if len(allTypes) == 0 {
		return models.ColumnFinding{}, false
	}

	mainType := primaryType(allTypes)
	method := detectionMethod(heuristicTypes, regexTypes)

	var anonSamples []string
	matchCount := 0
	for _, sample := range samples {
		if detected := DetectValue(sample); len(detected) > 0 {
			matchCount++
			if len(anonSamples) < 3 {
				anonSamples = append(anonSamples, Anonymize(sample, mainType))
			}
		}
	}

	return models.ColumnFinding{
		ColumnName:      col.Name,
		ColumnType:      col.DataType,
		PIITypes:        allTypes,
		RiskLevel:       models.HighestRisk(allTypes),
		DetectionMethod: method,
		SampleValues:    anonSamples,
		MatchCount:      matchCount,
	}, true
}

func detectInSamples(samples []string) []models.PIIType {
	seen := make(map[models.PIIType]bool)
	for _, s := range samples {
		for _, t := range DetectValue(s) {
			seen[t] = true
		}
	}
	result := make([]models.PIIType, 0, len(seen))
	for t := range seen {
		result = append(result, t)
	}
	return result
}

func mergeTypes(a, b []models.PIIType) []models.PIIType {
	seen := make(map[models.PIIType]bool)
	var result []models.PIIType
	for _, t := range append(a, b...) {
		if !seen[t] {
			seen[t] = true
			result = append(result, t)
		}
	}
	return result
}

func detectionMethod(heuristic, regex []models.PIIType) models.DetectionMethod {
	hasH := len(heuristic) > 0
	hasR := len(regex) > 0
	switch {
	case hasH && hasR:
		return models.DetectionBoth
	case hasR:
		return models.DetectionRegex
	default:
		return models.DetectionHeuristic
	}
}

func primaryType(types []models.PIIType) models.PIIType {
	order := map[models.RiskLevel]int{
		models.RiskCritical: 4, models.RiskHigh: 3,
		models.RiskMedium: 2, models.RiskLow: 1,
	}
	best := types[0]
	for _, t := range types[1:] {
		if order[models.RiskForPII(t)] > order[models.RiskForPII(best)] {
			best = t
		}
	}
	return best
}

func highestRiskFromColumns(cols []models.ColumnFinding) models.RiskLevel {
	order := map[models.RiskLevel]int{
		models.RiskCritical: 4, models.RiskHigh: 3,
		models.RiskMedium: 2, models.RiskLow: 1,
	}
	highest := models.RiskLow
	for _, c := range cols {
		if order[c.RiskLevel] > order[highest] {
			highest = c.RiskLevel
		}
	}
	return highest
}

func buildSummary(tables []models.TableFinding) models.RiskSummary {
	var s models.RiskSummary
	for _, t := range tables {
		for _, c := range t.PIIColumns {
			switch c.RiskLevel {
			case models.RiskCritical:
				s.Critical++
			case models.RiskHigh:
				s.High++
			case models.RiskMedium:
				s.Medium++
			case models.RiskLow:
				s.Low++
			}
		}
	}
	return s
}
