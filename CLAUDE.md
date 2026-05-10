# PII Hunter — Guia para Claude Code

## O que é este projeto

**PII Hunter** é uma ferramenta CLI em Go que escaneia bancos de dados PostgreSQL (incluindo Supabase) em busca de dados pessoais (PII — Personally Identifiable Information), conforme exigido pela LGPD. Ao final do scan, gera relatórios em HTML e PDF.

Este projeto é desenvolvido com **Extreme Programming (XP)** e **Test-Driven Development (TDD)**.

---

## Regras inegociáveis de desenvolvimento

### TDD — sempre, sem exceção

O ciclo obrigatório para qualquer nova funcionalidade:

```
1. Escreva o teste (RED) → o teste deve falhar
2. Escreva o mínimo de código para passar (GREEN)
3. Refatore mantendo os testes verdes (REFACTOR)
```

**Nunca escreva código de produção sem um teste que o justifique.**

### XP Practices aplicadas

- **Small releases:** cada funcionalidade é uma unidade pequena e entregável
- **Simple design:** a solução mais simples que passa nos testes
- **Refactoring contínuo:** ao passar nos testes, melhore o código
- **Coding standards:** siga o padrão Go idiomático (`gofmt`, `golint`)
- **Collective ownership:** qualquer parte do código pode ser melhorada a qualquer momento

---

## Stack técnica

| Componente | Tecnologia |
|------------|-----------|
| Linguagem | Go 1.22+ |
| Banco de dados | PostgreSQL (compatível com Supabase) |
| Driver PostgreSQL | `lib/pq` |
| CLI | `flag` (stdlib) ou `cobra` |
| Geração HTML | `html/template` (stdlib) |
| Geração PDF | `github.com/go-pdf/fpdf` |
| Testes | `testing` (stdlib) + `testify` |
| Lint | `golangci-lint` |

---

## Estrutura do projeto

```
pii-hunter/
├── CLAUDE.md               ← este arquivo
├── README.md               ← documentação do usuário
├── SPEC.md                 ← especificação técnica completa
├── go.mod
├── go.sum
├── main.go                 ← entry point: lê flags e inicia o scan
├── cmd/
│   └── root.go             ← definição dos comandos CLI
├── scanner/
│   ├── connector.go        ← abre e valida conexão PostgreSQL
│   ├── connector_test.go
│   ├── inspector.go        ← lista schemas, tabelas, colunas
│   ├── inspector_test.go
│   ├── detector.go         ← aplica regex e heurísticas para detectar PII
│   └── detector_test.go
├── report/
│   ├── html.go             ← gera relatório HTML
│   ├── html_test.go
│   ├── pdf.go              ← gera relatório PDF
│   ├── pdf_test.go
│   └── templates/
│       └── report.html     ← template HTML do relatório
├── models/
│   ├── findings.go         ← structs: ScanResult, TableFinding, ColumnFinding, PIIType
│   └── findings_test.go
└── testdata/
    └── fixtures/
        └── seed.sql        ← banco de teste com dados fictícios para TDD
```

---

## Como rodar

```bash
# Instalar dependências
go mod tidy

# Rodar todos os testes
go test ./...

# Rodar testes com cobertura
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Build
go build -o pii-hunter .

# Executar (PostgreSQL local)
./pii-hunter --host localhost --port 5432 --db minhabase --user paula --password senha

# Executar (Supabase)
./pii-hunter --host db.XXXXXXXX.supabase.co --port 5432 --db postgres --user postgres --password suasenha

# Saída gerada em:
# ./reports/relatorio.html
# ./reports/relatorio.pdf
```

---

## Ordem de desenvolvimento (iterações XP)

Desenvolva nesta ordem. Cada item é uma iteração pequena com testes primeiro.

### Iteração 1 — Modelos de dados
- [ ] `models/findings.go` — definir todas as structs
- [ ] `models/findings_test.go` — testar criação e validação dos modelos

### Iteração 2 — Conexão com o banco
- [ ] `scanner/connector_test.go` — testar abertura de conexão e falha com credenciais erradas
- [ ] `scanner/connector.go` — implementar `Connect(config Config) (*sql.DB, error)`

### Iteração 3 — Inspeção do schema
- [ ] `scanner/inspector_test.go` — testar listagem de tabelas e colunas (usar banco de teste)
- [ ] `scanner/inspector.go` — implementar `GetTables()` e `GetColumns(table)`

### Iteração 4 — Detecção de PII
- [ ] `scanner/detector_test.go` — testar cada regex e heurística individualmente
- [ ] `scanner/detector.go` — implementar `Detect(value string) []PIIType` e `DetectByColumnName(col string) []PIIType`

### Iteração 5 — Orquestração do scan
- [ ] Integrar connector + inspector + detector em `scanner/scanner.go`
- [ ] Retornar `ScanResult` completo

### Iteração 6 — Relatório HTML
- [ ] `report/html_test.go` — testar que o HTML gerado contém os dados esperados
- [ ] `report/html.go` + `report/templates/report.html`

### Iteração 7 — Relatório PDF
- [ ] `report/pdf_test.go`
- [ ] `report/pdf.go`

### Iteração 8 — CLI
- [ ] `cmd/root.go` — flags, validação de entrada, orquestração
- [ ] `main.go` — entry point limpo

---

## Tipos de PII detectados

| Tipo | Estratégia | Exemplo |
|------|-----------|---------|
| CPF | Regex | `123.456.789-09` ou `12345678909` |
| CNPJ | Regex | `12.345.678/0001-90` |
| Email | Regex | `paula@email.com` |
| Telefone | Regex | `(61) 99999-9999` ou `+5561999999999` |
| Cartão de crédito | Regex (Luhn) | `4111 1111 1111 1111` |
| CEP | Regex | `70040-020` ou `70040020` |
| Data de nascimento | Regex + nome coluna | `1990-05-15`, coluna `data_nasc*` |
| Nome | Heurística de coluna | colunas `nome`, `name`, `full_name`, `nome_completo` |
| Endereço | Heurística de coluna | colunas `endereco`, `address`, `logradouro`, `rua` |

---

## Níveis de risco no relatório

| Risco | Cor | Critério |
|-------|-----|---------|
| CRÍTICO | 🔴 Vermelho | CPF, CNPJ, Cartão de crédito |
| ALTO | 🟠 Laranja | Email, Telefone, Data de nascimento |
| MÉDIO | 🟡 Amarelo | Nome, CEP |
| BAIXO | 🟢 Verde | Endereço (heurística de coluna apenas) |

---

## Padrões de código Go

```go
// Funções exportadas têm godoc
// Connect abre uma conexão com o banco PostgreSQL usando as configurações fornecidas.
// Retorna erro se a conexão falhar ou se o ping não responder.
func Connect(cfg Config) (*sql.DB, error) { ... }

// Erros são sempre tratados, nunca ignorados
db, err := Connect(cfg)
if err != nil {
    return fmt.Errorf("falha ao conectar: %w", err)
}

// Testes usam t.Run para subtestes
func TestDetect(t *testing.T) {
    t.Run("detecta CPF válido", func(t *testing.T) { ... })
    t.Run("ignora CPF inválido", func(t *testing.T) { ... })
}
```

---

## Variáveis de ambiente (alternativa às flags)

```
PII_HUNTER_HOST
PII_HUNTER_PORT
PII_HUNTER_DB
PII_HUNTER_USER
PII_HUNTER_PASSWORD
PII_HUNTER_OUTPUT_DIR
```

---

## Definition of Done para cada iteração

Uma iteração só está concluída quando:
- [ ] Todos os testes passam (`go test ./...`)
- [ ] Cobertura de testes ≥ 80% no pacote
- [ ] Código formatado (`gofmt -l .` não retorna nada)
- [ ] Sem erros de lint (`golangci-lint run`)
- [ ] Funções exportadas têm godoc
