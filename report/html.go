package report

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/piihunter/pii-hunter/models"
)

//go:embed templates/report.html
var reportHTMLTemplate string

// GenerateHTML gera o relatório HTML do scan e salva em outputDir/relatorio.html.
// O template é embarcado no binário via //go:embed — não requer arquivos externos.
func GenerateHTML(result models.ScanResult, outputDir string) error {
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("falha ao criar diretório de saída: %w", err)
	}

	tmpl, err := template.New("report").Parse(reportHTMLTemplate)
	if err != nil {
		return fmt.Errorf("falha ao parsear template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, result); err != nil {
		return fmt.Errorf("falha ao renderizar relatório: %w", err)
	}

	outPath := filepath.Join(outputDir, "relatorio.html")
	if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
		return fmt.Errorf("falha ao salvar arquivo: %w", err)
	}
	return nil
}
