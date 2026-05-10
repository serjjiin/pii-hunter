// Package report gera os relatórios HTML e PDF a partir dos resultados do scan.
package report

import (
	"fmt"
	"html/template"
	"os"
	"path/filepath"

	"github.com/piihunter/pii-hunter/models"
)

// GenerateHTML gera o relatório HTML do scan e salva em outputDir/relatorio.html.
func GenerateHTML(result models.ScanResult, outputDir string) error {
	// TODO: implementar após rodar os testes (TDD)
	// 1. Criar outputDir se não existir (os.MkdirAll)
	// 2. Carregar template de report/templates/report.html
	// 3. Executar template com result
	// 4. Salvar em outputDir/relatorio.html
	_ = result
	_ = template.New // import usado no futuro

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("falha ao criar diretório de saída: %w", err)
	}

	outPath := filepath.Join(outputDir, "relatorio.html")
	_ = outPath

	return fmt.Errorf("GenerateHTML: não implementado")
}
