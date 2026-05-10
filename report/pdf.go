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
	// TODO: implementar após rodar os testes (TDD)
	// 1. Criar outputDir se não existir
	// 2. Inicializar fpdf.New("P", "mm", "A4", "")
	// 3. Adicionar página de capa (título, banco, data, logotipo)
	// 4. Adicionar resumo executivo
	// 5. Para cada tabela com PII, adicionar seção com tabela de achados
	// 6. Adicionar página de recomendações
	// 7. Salvar em outputDir/relatorio.pdf

	_ = result
	_ = fpdf.New // import usado no futuro

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("falha ao criar diretório de saída: %w", err)
	}

	outPath := filepath.Join(outputDir, "relatorio.pdf")
	_ = outPath

	return fmt.Errorf("GeneratePDF: não implementado")
}
