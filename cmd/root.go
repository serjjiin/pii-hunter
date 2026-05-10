// Package cmd define os comandos da CLI do PII Hunter usando Cobra.
package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	host      string
	port      int
	database  string
	user      string
	password  string
	sslMode   string
	schema    string
	outputDir string
)

// rootCmd é o comando principal da CLI.
var rootCmd = &cobra.Command{
	Use:   "pii-hunter",
	Short: "PII Hunter — Scanner de dados pessoais para conformidade LGPD",
	Long: `
██████╗ ██╗██╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗ 
██╔══██╗██║██║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
██████╔╝██║██║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
██╔═══╝ ██║██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
██║     ██║██║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
╚═╝     ╚═╝╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

Escaneia bancos PostgreSQL em busca de dados pessoais (PII) conforme a LGPD.
Gera relatórios HTML e PDF prontos para uso como RoPA (Registro de Operações).

Exemplos:
  pii-hunter --host localhost --db minhabase --user paula --password senha
  pii-hunter --host db.xxx.supabase.co --db postgres --user postgres --password senha
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// TODO: implementar após as iterações de scanner e report (TDD)
		// 1. Validar flags obrigatórias (host, db, user, password)
		// 2. Criar models.Config
		// 3. Chamar scanner.Connect → scanner.Scan → report.GenerateHTML → report.GeneratePDF
		// 4. Exibir progresso no terminal com cores
		// 5. Exibir resumo final e caminho dos relatórios

		fmt.Println("🔍 PII Hunter — iniciando scan...")
		fmt.Printf("   Host:   %s:%d\n", host, port)
		fmt.Printf("   Banco:  %s\n", database)
		fmt.Printf("   Schema: %s\n", schema)
		fmt.Println()
		fmt.Println("⚠️  Scanner ainda não implementado. Siga as iterações no CLAUDE.md")

		return nil
	},
}

// Execute inicia a CLI.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.Flags().StringVar(&host, "host", "localhost", "endereço do servidor PostgreSQL")
	rootCmd.Flags().IntVar(&port, "port", 5432, "porta do servidor PostgreSQL")
	rootCmd.Flags().StringVar(&database, "db", "", "nome do banco de dados (obrigatório)")
	rootCmd.Flags().StringVar(&user, "user", "", "usuário do banco de dados (obrigatório)")
	rootCmd.Flags().StringVar(&password, "password", "", "senha do banco de dados (obrigatório)")
	rootCmd.Flags().StringVar(&sslMode, "ssl", "require", "modo SSL: disable | require | verify-full")
	rootCmd.Flags().StringVar(&schema, "schema", "public", "schema a escanear")
	rootCmd.Flags().StringVar(&outputDir, "output", "./reports", "diretório de saída dos relatórios")

	rootCmd.MarkFlagRequired("db")
	rootCmd.MarkFlagRequired("user")
	rootCmd.MarkFlagRequired("password")
}
