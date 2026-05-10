# PII Hunter — Especificação Técnica

**Versão:** 1.0  
**Data:** 2026-05  
**Autora:** Paula  
**Contexto:** Projeto de pós-graduação em Segurança da Informação — Módulo 3: Privacy and Data Protection / Data Mapping and Privacy Governance

---

## 1. Visão do Produto

### 1.1 Problema

A LGPD (Lei Geral de Proteção de Dados — Lei 13.709/2018) exige que toda organização saiba **onde estão os dados pessoais** que ela trata. Esse mapeamento é chamado de **Registro de Operações de Tratamento** (RoPA) e é obrigatório.

Na prática, a maioria das organizações realiza esse mapeamento de forma **manual e imprecisa** — entrevistando pessoas, olhando documentações antigas ou simplesmente chutando. Isso gera:

- Risco de multas de até R$ 50 milhões por infração (Art. 52 da LGPD)
- Dados pessoais expostos em tabelas esquecidas
- Incapacidade de responder a pedidos de titulares (Art. 18 da LGPD)
- Falha nas avaliações da ANPD

### 1.2 Solução

O **PII Hunter** é uma ferramenta de linha de comando (CLI) que:

1. Conecta ao banco PostgreSQL da organização (local ou Supabase)
2. Inspeciona automaticamente todas as tabelas e colunas
3. Detecta dados pessoais por **regex** (padrões estruturados) e **heurística** (nomes de colunas)
4. Classifica os achados por **nível de risco** (LGPD)
5. Gera um relatório profissional em **HTML e PDF** pronto para usar como RoPA inicial

### 1.3 Público-alvo

- **DPOs (Data Protection Officers)** que precisam fazer mapeamento rápido
- **Desenvolvedores** que querem auditar seus próprios bancos
- **Consultorias de LGPD** que atendem múltiplos clientes

---

## 2. Requisitos Funcionais

### RF-01 — Conexão com banco de dados
- O sistema deve aceitar conexão com bancos PostgreSQL via parâmetros de CLI
- Deve suportar conexão com Supabase (PostgreSQL gerenciado)
- Deve validar a conexão antes de iniciar o scan
- Deve exibir erro claro em caso de falha de conexão

**Parâmetros:**
```
--host      endereço do servidor (padrão: localhost)
--port      porta (padrão: 5432)
--db        nome do banco de dados
--user      usuário
--password  senha
--ssl       modo SSL: disable | require | verify-full (padrão: require)
--schema    schema a escanear (padrão: public)
--output    diretório de saída (padrão: ./reports)
```

### RF-02 — Inspeção do schema
- O sistema deve listar todos os schemas disponíveis
- Deve listar todas as tabelas do schema selecionado
- Deve listar todas as colunas de cada tabela com seus tipos

### RF-03 — Detecção de PII por regex
O sistema deve detectar os seguintes tipos de PII usando expressões regulares aplicadas aos **valores** das colunas (amostragem de até 1000 linhas por coluna):

| ID | Tipo PII | Regex |
|----|----------|-------|
| P01 | CPF | `\b\d{3}[\.\s]?\d{3}[\.\s]?\d{3}[-\.\s]?\d{2}\b` |
| P02 | CNPJ | `\b\d{2}[\.\s]?\d{3}[\.\s]?\d{3}[\/\.\s]?\d{4}[-\.\s]?\d{2}\b` |
| P03 | Email | `\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b` |
| P04 | Telefone BR | `(\+55\s?)?\(?\d{2}\)?\s?\d{4,5}[\-\s]?\d{4}` |
| P05 | Cartão de crédito | `\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b` |
| P06 | CEP | `\b\d{5}[-\s]?\d{3}\b` |
| P07 | Data de nascimento | `\b\d{4}[-\/]\d{2}[-\/]\d{2}\b` ou `\b\d{2}[-\/]\d{2}[-\/]\d{4}\b` |

### RF-04 — Detecção de PII por heurística de coluna
O sistema deve detectar PII pela análise do **nome da coluna**, independente do valor:

| Tipo PII | Padrões de nome de coluna (case-insensitive) |
|----------|---------------------------------------------|
| Nome | `nome`, `name`, `full_name`, `nome_completo`, `primeiro_nome`, `sobrenome`, `first_name`, `last_name` |
| Endereço | `endereco`, `address`, `logradouro`, `rua`, `avenida`, `complemento`, `bairro` |
| Data nascimento | `data_nasc`, `nascimento`, `birth_date`, `birthdate`, `dob`, `dt_nasc` |
| CPF | `cpf`, `documento`, `doc_number` |
| Email | `email`, `e_mail`, `email_address`, `correio` |
| Telefone | `telefone`, `celular`, `fone`, `phone`, `mobile`, `tel` |

### RF-05 — Classificação de risco
Cada achado deve ser classificado:

| Nível | Tipos de PII | Ação recomendada |
|-------|-------------|-----------------|
| CRÍTICO | CPF, CNPJ, Cartão de crédito | Criptografar imediatamente, acesso restrito |
| ALTO | Email, Telefone, Data de nascimento | Pseudonimizar, revisar acessos |
| MÉDIO | Nome, CEP | Documentar no RoPA, avaliar necessidade |
| BAIXO | Endereço (heurística) | Monitorar, confirmar manualmente |

### RF-06 — Relatório HTML
O relatório HTML deve conter:
- Cabeçalho com data/hora do scan, banco escaneado, duração
- Resumo executivo: total de tabelas, total de colunas com PII, distribuição por risco
- Tabela detalhada por tabela → coluna → tipo de PII → risco → amostra anonimizada
- Recomendações por nível de risco
- Rodapé com referência à LGPD (Art. 37, 46, 52)

### RF-07 — Relatório PDF
- Conteúdo equivalente ao HTML
- Formatação profissional (cabeçalho, paginação, logotipo)
- Adequado para envio formal ao DPO ou ANPD

### RF-08 — Anonimização de amostras
- Ao exibir exemplos de valores encontrados, **sempre** anonimizar parcialmente
- CPF: `***.456.789-**`
- Email: `p***@email.com`
- Cartão: `**** **** **** 1111`

---

## 3. Requisitos Não Funcionais

| ID | Requisito |
|----|-----------|
| RNF-01 | O scan de um banco com 100 tabelas deve completar em menos de 2 minutos |
| RNF-02 | O sistema não deve armazenar dados pessoais em nenhum arquivo temporário |
| RNF-03 | Conexões com o banco devem usar SSL por padrão |
| RNF-04 | O binário deve ser cross-platform: Linux, macOS, Windows |
| RNF-05 | Cobertura de testes ≥ 80% em todos os pacotes |
| RNF-06 | A amostragem de valores não deve exceder 1000 linhas por coluna |

---

## 4. Modelos de Dados

```go
// PIIType representa um tipo de dado pessoal detectado
type PIIType string

const (
    PIITypeCPF           PIIType = "CPF"
    PIITypeCNPJ          PIIType = "CNPJ"
    PIITypeEmail         PIIType = "Email"
    PIITypePhone         PIIType = "Telefone"
    PIITypeCreditCard    PIIType = "Cartão de Crédito"
    PIITypeCEP           PIIType = "CEP"
    PIITypeBirthDate     PIIType = "Data de Nascimento"
    PIITypeName          PIIType = "Nome"
    PIITypeAddress       PIIType = "Endereço"
)

// RiskLevel representa o nível de risco LGPD
type RiskLevel string

const (
    RiskCritical RiskLevel = "CRÍTICO"
    RiskHigh     RiskLevel = "ALTO"
    RiskMedium   RiskLevel = "MÉDIO"
    RiskLow      RiskLevel = "BAIXO"
)

// ColumnFinding representa um achado em uma coluna específica
type ColumnFinding struct {
    ColumnName      string
    ColumnType      string      // tipo SQL da coluna
    PIITypes        []PIIType
    RiskLevel       RiskLevel
    DetectionMethod string      // "regex" | "heuristica" | "ambos"
    SampleValues    []string    // valores anonimizados
    MatchCount      int         // quantas linhas tiveram match
}

// TableFinding representa todos os achados em uma tabela
type TableFinding struct {
    TableName      string
    Schema         string
    TotalColumns   int
    PIIColumns     []ColumnFinding
    HighestRisk    RiskLevel
}

// ScanResult é o resultado completo de um scan
type ScanResult struct {
    Host           string
    Database       string
    Schema         string
    ScannedAt      time.Time
    DurationSec    float64
    TotalTables    int
    TotalColumns   int
    TotalPIICols   int
    Tables         []TableFinding
    Summary        RiskSummary
}

// RiskSummary consolida achados por nível de risco
type RiskSummary struct {
    Critical int
    High     int
    Medium   int
    Low      int
}

// Config representa a configuração de conexão
type Config struct {
    Host     string
    Port     int
    Database string
    User     string
    Password string
    SSLMode  string
    Schema   string
    OutputDir string
}
```

---

## 5. Arquitetura e Fluxo

```
┌─────────────────────────────────────────────────────┐
│                    CLI (main.go)                    │
│         Lê flags → valida → chama Scanner           │
└───────────────────────┬─────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────────┐
│                   Scanner                           │
│                                                     │
│  Connector ──► Inspector ──► Detector               │
│  (conexão)    (tabelas/    (regex +                 │
│               colunas)     heurística)              │
│                                                     │
│              Retorna: ScanResult                    │
└───────────────────────┬─────────────────────────────┘
                        │
              ┌─────────┴─────────┐
              ▼                   ▼
┌─────────────────┐   ┌─────────────────┐
│  report/html.go │   │  report/pdf.go  │
│  → relatorio    │   │  → relatorio    │
│    .html        │   │    .pdf         │
└─────────────────┘   └─────────────────┘
```

---

## 6. Plano de Testes

### 6.1 Testes unitários (TDD)

Cada função tem testes antes da implementação:

```
scanner/detector_test.go
  TestDetectCPF
    - detecta CPF com pontuação (123.456.789-09)
    - detecta CPF sem pontuação (12345678909)
    - ignora sequências inválidas (111.111.111-11)
    - ignora texto sem CPF

  TestDetectEmail
    - detecta email simples
    - detecta email com subdomínio
    - ignora texto sem @

  TestDetectByColumnName
    - detecta "nome" como PIITypeName
    - detecta "cpf" como PIITypeCPF
    - retorna vazio para coluna "id"
    - é case-insensitive

scanner/inspector_test.go
  TestGetTables
    - retorna lista de tabelas do schema public
    - retorna erro se schema não existe

scanner/connector_test.go
  TestConnect
    - conecta com credenciais válidas
    - retorna erro com credenciais inválidas
    - retorna erro com host inválido

report/html_test.go
  TestGenerateHTML
    - gera arquivo HTML
    - HTML contém nome do banco
    - HTML contém tabelas com PII encontrado
    - valores são anonimizados
```

### 6.2 Dados de teste (fixtures)

`testdata/fixtures/seed.sql` cria um banco com:
- Tabela `usuarios` com CPF, email, telefone
- Tabela `pedidos` com endereço de entrega
- Tabela `pagamentos` com número de cartão
- Tabela `produtos` sem nenhum PII (para validar falsos positivos)

---

## 7. Referências Legais

- **LGPD — Lei 13.709/2018**
  - Art. 5º, I — Definição de dado pessoal
  - Art. 37 — Obrigação de manter registro de operações de tratamento
  - Art. 46 — Medidas de segurança técnicas e administrativas
  - Art. 52 — Sanções administrativas (multa até 2% do faturamento, limitado a R$ 50 mi)
- **ANPD — Resolução CD/ANPD nº 2/2022** — Regulamento de fiscalização
- **ISO 27701:2019** — Extensão de privacidade à ISO 27001

---

## 8. Possíveis Desdobramentos

| Versão | Funcionalidade |
|--------|---------------|
| v1.1 | Suporte a MySQL e SQLite |
| v1.2 | Modo `--watch`: scan agendado com alertas por email |
| v1.3 | Integração com CI/CD (GitHub Actions) |
| v2.0 | Interface web para múltiplos bancos |
| v2.1 | SaaS multi-tenant para consultorias LGPD |
| v3.0 | Suporte a MongoDB, S3, arquivos CSV |
