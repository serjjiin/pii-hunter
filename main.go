// PII Hunter — Ferramenta CLI de detecção de dados pessoais em bancos PostgreSQL
// Desenvolvida para conformidade com a LGPD (Lei 13.709/2018)
//
// Uso:
//
//	./pii-hunter --host localhost --db minhabase --user paula --password senha
package main

import (
	"fmt"
	"os"

	"github.com/piihunter/pii-hunter/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Erro: %v\n", err)
		os.Exit(1)
	}
}
