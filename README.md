# 🔍 PII Hunter

> Scanner de dados pessoais para conformidade com a LGPD — feito em Go

[![Go Version](https://img.shields.io/badge/Go-1.22+-blue.svg)](https://golang.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![LGPD](https://img.shields.io/badge/LGPD-compliant-orange.svg)](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm)

## O que é

O **PII Hunter** escaneia bancos de dados PostgreSQL (incluindo Supabase) em busca de dados pessoais (PII — *Personally Identifiable Information*), conforme exigido pela **LGPD (Lei 13.709/2018)**.

Ao final do scan, gera um relatório em **HTML** e **PDF** pronto para ser usado como ponto de partida do seu **RoPA (Registro de Operações de Tratamento)**.

## Por que isso importa

A LGPD exige que toda organização saiba onde estão os dados pessoais que ela trata (Art. 37). Empresas que não têm esse mapeamento estão sujeitas a multas de até **R$ 50 milhões por infração** (Art. 52).

O PII Hunter automatiza a parte mais trabalhosa desse processo.

## Dados detectados

| Tipo | Como detecta | Risco LGPD |
|------|-------------|-----------|
| CPF | Regex | 🔴 CRÍTICO |
| CNPJ | Regex | 🔴 CRÍTICO |
| Cartão de crédito | Regex | 🔴 CRÍTICO |
| Email | Regex | 🟠 ALTO |
| Telefone | Regex | 🟠 ALTO |
| Data de nascimento | Regex + heurística | 🟠 ALTO |
| Nome | Heurística de coluna | 🟡 MÉDIO |
| CEP | Regex | 🟡 MÉDIO |
| Endereço | Heurística de coluna | 🟢 BAIXO |

## Instalação

```bash
# Clone o repositório
git clone https://github.com/piihunter/pii-hunter.git
cd pii-hunter

# Instale dependências
go mod tidy

# Build
go build -o pii-hunter .
```

## Uso

```bash
# PostgreSQL local
./pii-hunter --host localhost --db minhabase --user paula --password senha

# Supabase
./pii-hunter --host db.XXXXXXXX.supabase.co --db postgres --user postgres --password suasenha

# Especificar schema e diretório de saída
./pii-hunter --host localhost --db minhabase --user paula --password senha \
             --schema public --output ./meus-relatorios
```

### Todas as flags

| Flag | Padrão | Descrição |
|------|--------|-----------|
| `--host` | `localhost` | Endereço do servidor |
| `--port` | `5432` | Porta do servidor |
| `--db` | — | Nome do banco (obrigatório) |
| `--user` | — | Usuário (obrigatório) |
| `--password` | — | Senha (obrigatório) |
| `--ssl` | `require` | Modo SSL: `disable`, `require`, `verify-full` |
| `--schema` | `public` | Schema a escanear |
| `--output` | `./reports` | Diretório de saída |

### Variáveis de ambiente

```bash
export PII_HUNTER_HOST=localhost
export PII_HUNTER_DB=minhabase
export PII_HUNTER_USER=paula
export PII_HUNTER_PASSWORD=senha
./pii-hunter
```

## Saída

Após o scan, dois arquivos são gerados no diretório `--output`:

```
./reports/
├── relatorio.html   # Relatório interativo com filtros
└── relatorio.pdf    # Relatório formal para envio ao DPO
```

O relatório inclui:
- Resumo executivo com distribuição de risco
- Tabela detalhada por schema → tabela → coluna → tipo de PII
- Amostras **anonimizadas** dos valores encontrados
- Recomendações por nível de risco
- Referências legais (LGPD Art. 37, 46, 52)

## Desenvolvimento

Este projeto usa **Extreme Programming (XP)** e **Test-Driven Development (TDD)**.

```bash
# Rodar todos os testes
go test ./...

# Rodar testes com cobertura
go test ./... -coverprofile=coverage.out
go tool cover -html=coverage.out

# Lint
golangci-lint run

# Formatar código
gofmt -w .
```

Veja [CLAUDE.md](CLAUDE.md) para as instruções completas de desenvolvimento.  
Veja [SPEC.md](SPEC.md) para a especificação técnica detalhada.

## Roadmap

- [x] v1.0 — PostgreSQL + HTML + PDF + CLI
- [ ] v1.1 — Suporte a MySQL e SQLite
- [ ] v1.2 — Modo `--watch` com alertas por email
- [ ] v1.3 — Integração com CI/CD (GitHub Actions)
- [ ] v2.0 — Interface web para múltiplos bancos
- [ ] v2.1 — SaaS multi-tenant para consultorias LGPD

## Referências legais

- [LGPD — Lei 13.709/2018](https://www.planalto.gov.br/ccivil_03/_ato2015-2018/2018/lei/l13709.htm)
- [ANPD — Resolução CD/ANPD nº 2/2022](https://www.gov.br/anpd)
- [ISO 27701:2019](https://www.iso.org/standard/71670.html)

## Licença

MIT — veja [LICENSE](LICENSE)
