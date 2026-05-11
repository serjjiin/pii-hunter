package cmd

import (
	"fmt"

	"github.com/piihunter/pii-hunter/models"
	"github.com/piihunter/pii-hunter/report"
	"github.com/piihunter/pii-hunter/scanner"
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

var rootCmd = &cobra.Command{
	Use:   "pii-hunter",
	Short: "PII Hunter — Scanner de dados pessoais para conformidade LGPD",
	Long: `
PII Hunter — Scanner de dados pessoais para conformidade com a LGPD (Lei 13.709/2018).

Escaneia bancos PostgreSQL em busca de dados pessoais (PII) e gera relatórios
HTML e PDF prontos para uso como RoPA (Registro de Operações de Tratamento).

Exemplos:
  pii-hunter --host localhost --db minhabase --user paula --password senha
  pii-hunter --host db.xxx.supabase.co --db postgres --user postgres --password senha
`,
	RunE: func(cmd *cobra.Command, args []string) error {
		if database == "" || user == "" || password == "" {
			return fmt.Errorf("flags obrigatórias: --db, --user, --password")
		}

		cfg := models.Config{
			Host:      host,
			Port:      port,
			Database:  database,
			User:      user,
			Password:  password,
			SSLMode:   sslMode,
			Schema:    schema,
			OutputDir: outputDir,
		}

		fmt.Println("\n🔍 PII Hunter — iniciando scan...")
		fmt.Printf("   Host:   %s:%d\n", host, port)
		fmt.Printf("   Banco:  %s\n", database)
		fmt.Printf("   Schema: %s\n\n", schema)

		fmt.Println("Conectando ao banco de dados...")
		db, err := scanner.Connect(cfg)
		if err != nil {
			return fmt.Errorf("falha ao conectar: %w", err)
		}
		defer db.Close()
		fmt.Println("✓ Conexão estabelecida")

		fmt.Println("Escaneando schema em busca de dados pessoais...")
		s := scanner.NewScanner(db, cfg)
		result, err := s.Scan()
		if err != nil {
			return fmt.Errorf("falha ao escanear: %w", err)
		}
		fmt.Printf("✓ Scan concluído em %.2fs\n", result.DurationSec)

		fmt.Println("Gerando relatórios...")
		if err := report.GenerateHTML(result, cfg.OutputDir); err != nil {
			return fmt.Errorf("falha ao gerar HTML: %w", err)
		}
		if err := report.GeneratePDF(result, cfg.OutputDir); err != nil {
			return fmt.Errorf("falha ao gerar PDF: %w", err)
		}
		fmt.Printf("✓ Relatórios salvos em %s/\n", cfg.OutputDir)

		fmt.Println("\n═══════════════════════════════════")
		fmt.Println("  Resumo do Scan")
		fmt.Println("═══════════════════════════════════")
		fmt.Printf("  Tabelas escaneadas:    %d\n", result.TotalTables)
		fmt.Printf("  Colunas escaneadas:    %d\n", result.TotalColumns)
		fmt.Printf("  Colunas com PII:       %d\n", result.TotalPIICols)
		fmt.Println("  ─────────────────────────────")
		fmt.Printf("  🔴 CRÍTICO: %d  |  🟠 ALTO: %d  |  🟡 MÉDIO: %d  |  🟢 BAIXO: %d\n",
			result.Summary.Critical, result.Summary.High,
			result.Summary.Medium, result.Summary.Low)
		if len(result.Warnings) > 0 {
			fmt.Printf("  ⚠️  %d aviso(s) durante o scan\n", len(result.Warnings))
		}
		fmt.Print("═══════════════════════════════════\n")

		return nil
	},
}

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
}
