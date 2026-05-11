package report

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/go-pdf/fpdf"
	"github.com/piihunter/pii-hunter/models"
)

// GeneratePDF gera o relatório PDF do scan e salva em outputDir/relatorio.pdf.
func GeneratePDF(result models.ScanResult, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("falha ao criar diretório de saída: %w", err)
	}

	pdf := fpdf.New("P", "mm", "A4", "")
	pdf.SetMargins(20, 20, 20)
	pdf.SetAutoPageBreak(true, 20)
	pdf.SetHeaderFunc(func() {
		pdf.SetFont("Helvetica", "I", 8)
		pdf.SetTextColor(128, 128, 128)
		pdf.CellFormat(0, 8, "PII Hunter — Relatório de Dados Pessoais (LGPD)", "", 0, "C", false, 0, "")
		pdf.Ln(10)
	})
	pdf.SetFooterFunc(func() {
		pdf.SetY(-15)
		pdf.SetFont("Helvetica", "I", 7)
		pdf.SetTextColor(150, 150, 150)
		pdf.CellFormat(0, 10, fmt.Sprintf("Página %d — Gerado em %s",
			pdf.PageNo(),
			result.ScannedAt.Format("02/01/2006 15:04:05")),
			"", 0, "C", false, 0, "")
	})

	pdf.AddPage()

	// ── Capa ──────────────────────────────────────────────
	renderCover(pdf, result)

	// ── Resumo Executivo ──────────────────────────────────
	renderSummary(pdf, result)

	// ── Achados por Tabela ────────────────────────────────
	renderFindings(pdf, result)

	// ── Recomendações ─────────────────────────────────────
	renderRecommendations(pdf)

	// ── Warnings ──────────────────────────────────────────
	if len(result.Warnings) > 0 {
		renderWarnings(pdf, result.Warnings)
	}

	outPath := filepath.Join(outputDir, "relatorio.pdf")
	if err := pdf.OutputFileAndClose(outPath); err != nil {
		return fmt.Errorf("falha ao salvar PDF: %w", err)
	}
	return nil
}

func renderCover(pdf *fpdf.Fpdf, result models.ScanResult) {
	pdf.SetFont("Helvetica", "B", 22)
	pdf.SetTextColor(192, 57, 43)
	pdf.CellFormat(0, 14, "PII Hunter", "", 1, "C", false, 0, "")
	pdf.SetFont("Helvetica", "", 14)
	pdf.SetTextColor(44, 62, 80)
	pdf.CellFormat(0, 10, "Relatório de Dados Pessoais", "", 1, "C", false, 0, "")
	pdf.Ln(8)

	pdf.SetDrawColor(200, 200, 200)
	pdf.Line(20, pdf.GetY(), 190, pdf.GetY())
	pdf.Ln(8)

	pdf.SetFont("Helvetica", "", 11)
	pdf.SetTextColor(60, 60, 60)
	meta := [][2]string{
		{"Banco de dados", result.Database},
		{"Schema", result.Schema},
		{"Host", result.Host},
		{"Data do scan", result.ScannedAt.Format("02/01/2006 15:04:05")},
		{"Duração", fmt.Sprintf("%.2f segundos", result.DurationSec)},
		{"Tabelas escaneadas", fmt.Sprintf("%d", result.TotalTables)},
		{"Colunas escaneadas", fmt.Sprintf("%d", result.TotalColumns)},
		{"Colunas com PII", fmt.Sprintf("%d", result.TotalPIICols)},
	}
	for _, m := range meta {
		pdf.SetFont("Helvetica", "B", 11)
		pdf.CellFormat(55, 8, m[0]+":", "", 0, "R", false, 0, "")
		pdf.SetFont("Helvetica", "", 11)
		pdf.CellFormat(0, 8, m[1], "", 1, "L", false, 0, "")
	}
	pdf.Ln(6)
}

func renderSummary(pdf *fpdf.Fpdf, result models.ScanResult) {
	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetTextColor(44, 62, 80)
	pdf.CellFormat(0, 10, "Resumo Executivo", "", 1, "L", false, 0, "")
	pdf.Ln(4)

	risks := []struct {
		label         string
		count         int
		r, g, b       int
		bgR, bgG, bgB int
	}{
		{"CRÍTICO", result.Summary.Critical, 255, 255, 255, 231, 76, 60},
		{"ALTO", result.Summary.High, 255, 255, 255, 230, 126, 34},
		{"MÉDIO", result.Summary.Medium, 34, 34, 34, 241, 196, 15},
		{"BAIXO", result.Summary.Low, 255, 255, 255, 46, 204, 113},
	}

	colW := 42.5
	for _, r := range risks {
		pdf.SetFillColor(r.bgR, r.bgG, r.bgB)
		pdf.SetTextColor(r.r, r.g, r.b)
		pdf.SetFont("Helvetica", "B", 13)
		pdf.CellFormat(colW, 14, r.label, "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)
	for _, r := range risks {
		pdf.SetFillColor(r.bgR, r.bgG, r.bgB)
		pdf.SetTextColor(r.r, r.g, r.b)
		pdf.SetFont("Helvetica", "B", 18)
		pdf.CellFormat(colW, 16, fmt.Sprintf("%d", r.count), "1", 0, "C", true, 0, "")
	}
	pdf.Ln(-1)
	for _, r := range risks {
		pdf.SetFillColor(r.bgR, r.bgG, r.bgB)
		pdf.SetTextColor(r.r, r.g, r.b)
		pdf.SetFont("Helvetica", "", 10)
		pdf.CellFormat(colW, 10, "coluna(s)", "1", 0, "C", true, 0, "")
	}
	pdf.Ln(14)
}

func renderFindings(pdf *fpdf.Fpdf, result models.ScanResult) {
	if len(result.Tables) == 0 {
		pdf.SetFont("Helvetica", "I", 11)
		pdf.SetTextColor(100, 100, 100)
		pdf.CellFormat(0, 10, "Nenhum dado pessoal encontrado nas tabelas escaneadas.", "", 1, "L", false, 0, "")
		pdf.Ln(4)
		return
	}

	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetTextColor(44, 62, 80)
	pdf.CellFormat(0, 10, "Achados por Tabela", "", 1, "L", false, 0, "")
	pdf.Ln(4)

	for _, table := range result.Tables {
		if pdf.GetY() > 230 {
			pdf.AddPage()
		}

		pdf.SetFont("Helvetica", "B", 12)
		pdf.SetTextColor(44, 62, 80)
		pdf.CellFormat(0, 8, fmt.Sprintf("%s.%s  (%d coluna(s) com PII)",
			table.Schema, table.TableName, len(table.PIIColumns)), "", 1, "L", false, 0, "")
		pdf.Ln(3)

		// Cabeçalho da tabela
		headers := []string{"Coluna", "Tipo SQL", "PII Detectado", "Risco", "Método", "Matches"}
		widths := []float64{38, 28, 36, 22, 22, 24}
		pdf.SetFont("Helvetica", "B", 8)
		pdf.SetFillColor(44, 62, 80)
		pdf.SetTextColor(255, 255, 255)
		for i, h := range headers {
			pdf.CellFormat(widths[i], 8, h, "1", 0, "C", true, 0, "")
		}
		pdf.Ln(-1)

		// Linhas da tabela
		pdf.SetFont("Helvetica", "", 7)
		for _, col := range table.PIIColumns {
			riskColor := riskTextColor(col.RiskLevel)
			pdf.SetTextColor(60, 60, 60)

			rowH := 6.0
			pdf.CellFormat(widths[0], rowH, truncate(col.ColumnName, 24), "1", 0, "L", false, 0, "")
			pdf.CellFormat(widths[1], rowH, col.ColumnType, "1", 0, "C", false, 0, "")
			pdf.CellFormat(widths[2], rowH, truncate(joinTypes(col.PIITypes), 24), "1", 0, "L", false, 0, "")
			pdf.SetTextColor(riskColor.r, riskColor.g, riskColor.b)
			pdf.SetFont("Helvetica", "B", 7)
			pdf.CellFormat(widths[3], rowH, string(col.RiskLevel), "1", 0, "C", false, 0, "")
			pdf.SetFont("Helvetica", "", 7)
			pdf.SetTextColor(60, 60, 60)
			pdf.CellFormat(widths[4], rowH, string(col.DetectionMethod), "1", 0, "C", false, 0, "")
			pdf.CellFormat(widths[5], rowH, fmt.Sprintf("%d", col.MatchCount), "1", 1, "C", false, 0, "")

			// Amostras em linha separada
			if len(col.SampleValues) > 0 {
				samplesText := "Amostras: "
				for i, s := range col.SampleValues {
					if i > 0 {
						samplesText += ", "
					}
					samplesText += s
				}
				pdf.SetFont("Helvetica", "I", 6)
				pdf.SetTextColor(120, 120, 120)
				pdf.CellFormat(0, 5, "  "+truncate(samplesText, 170), "", 1, "L", false, 0, "")
			}
		}
		pdf.Ln(6)
	}
}

func renderRecommendations(pdf *fpdf.Fpdf) {
	if pdf.GetY() > 220 {
		pdf.AddPage()
	}

	pdf.SetFont("Helvetica", "B", 14)
	pdf.SetTextColor(44, 62, 80)
	pdf.CellFormat(0, 10, "Recomendações", "", 1, "L", false, 0, "")
	pdf.Ln(4)

	recs := []struct {
		risk    string
		text    string
		r, g, b int
	}{
		{"CRÍTICO", "CPF, CNPJ, Cartão de crédito: Criptografar imediatamente, restringir acessos, registrar no RoPA.", 231, 76, 60},
		{"ALTO", "Email, Telefone, Data de nascimento: Pseudonimizar, revisar permissões de acesso.", 230, 126, 34},
		{"MÉDIO", "Nome, CEP: Documentar no RoPA, avaliar necessidade de tratamento.", 241, 196, 15},
		{"BAIXO", "Endereço por heurística: Confirmar manualmente se é dado pessoal real.", 46, 204, 113},
	}

	pdf.SetFont("Helvetica", "", 10)
	for _, rec := range recs {
		pdf.SetTextColor(rec.r, rec.g, rec.b)
		pdf.SetFont("Helvetica", "B", 10)
		pdf.CellFormat(22, 7, rec.risk, "", 0, "R", false, 0, "")
		pdf.SetFont("Helvetica", "", 10)
		pdf.SetTextColor(60, 60, 60)
		pdf.CellFormat(0, 7, rec.text, "", 1, "L", false, 0, "")
		pdf.Ln(2)
	}
	pdf.Ln(4)

	pdf.SetFont("Helvetica", "I", 8)
	pdf.SetTextColor(150, 150, 150)
	pdf.CellFormat(0, 6, "Referências: LGPD Art. 37 (RoPA), Art. 46 (segurança técnica), Art. 52 (sanções até R$ 50 mi)", "", 1, "L", false, 0, "")
	pdf.CellFormat(0, 6, "Gerado por PII Hunter — github.com/serjjiin/pii-hunter", "", 1, "L", false, 0, "")
}

func renderWarnings(pdf *fpdf.Fpdf, warnings []string) {
	if pdf.GetY() > 240 {
		pdf.AddPage()
	}

	pdf.SetFont("Helvetica", "B", 12)
	pdf.SetTextColor(230, 126, 34)
	pdf.CellFormat(0, 10, "Avisos", "", 1, "L", false, 0, "")
	pdf.Ln(2)

	pdf.SetFont("Helvetica", "", 9)
	pdf.SetTextColor(80, 80, 80)
	for _, w := range warnings {
		pdf.CellFormat(0, 6, w, "", 1, "L", false, 0, "")
	}
	pdf.Ln(4)
}

type rgb struct{ r, g, b int }

func riskTextColor(level models.RiskLevel) rgb {
	switch level {
	case models.RiskCritical:
		return rgb{192, 57, 43}
	case models.RiskHigh:
		return rgb{230, 126, 34}
	case models.RiskMedium:
		return rgb{212, 172, 13}
	case models.RiskLow:
		return rgb{39, 174, 96}
	default:
		return rgb{60, 60, 60}
	}
}

func truncate(s string, max int) string {
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max-2]) + ".."
}

func joinTypes(types []models.PIIType) string {
	result := ""
	for i, t := range types {
		if i > 0 {
			result += ", "
		}
		result += string(t)
	}
	return result
}
