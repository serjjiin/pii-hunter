-- PII Hunter — Dados de teste (fixtures)
-- Use este script para criar o banco de teste antes de rodar os testes de integração
-- ATENÇÃO: todos os dados abaixo são FICTÍCIOS, gerados apenas para testes

-- Criar schema de teste
DROP TABLE IF EXISTS pagamentos;
DROP TABLE IF EXISTS pedidos;
DROP TABLE IF EXISTS usuarios;
DROP TABLE IF EXISTS produtos;

-- Tabela COM PII: dados de usuários
CREATE TABLE usuarios (
    id          SERIAL PRIMARY KEY,
    nome        VARCHAR(100),           -- PII: Nome (heurística)
    email       VARCHAR(200),           -- PII: Email (regex)
    cpf         VARCHAR(20),            -- PII: CPF (regex + heurística)
    telefone    VARCHAR(20),            -- PII: Telefone (regex + heurística)
    data_nasc   DATE,                   -- PII: Data de nascimento (heurística)
    created_at  TIMESTAMP DEFAULT NOW()
);

INSERT INTO usuarios (nome, email, cpf, telefone, data_nasc) VALUES
    ('João Silva',      'joao.silva@email.com',  '123.456.789-09', '(61) 98888-1111', '1985-03-22'),
    ('Maria Souza',     'maria@empresa.com.br',  '987.654.321-00', '(11) 97777-2222', '1990-07-15'),
    ('Carlos Pereira',  'carlos.p@mail.com',     '456.789.123-01', '(21) 96666-3333', '1978-12-01'),
    ('Ana Lima',        'ana.lima@test.org',     '321.654.987-02', '(31) 95555-4444', '2000-01-30'),
    ('Pedro Costa',     'p.costa@dominio.net',   '654.987.321-03', '(41) 94444-5555', '1995-09-10');

-- Tabela COM PII: pedidos com endereço de entrega
CREATE TABLE pedidos (
    id              SERIAL PRIMARY KEY,
    usuario_id      INTEGER REFERENCES usuarios(id),
    logradouro      VARCHAR(200),       -- PII: Endereço (heurística)
    complemento     VARCHAR(100),       -- PII: Endereço (heurística)
    bairro          VARCHAR(100),       -- PII: Endereço (heurística)
    cep             VARCHAR(10),        -- PII: CEP (regex + heurística)
    total           DECIMAL(10, 2),
    created_at      TIMESTAMP DEFAULT NOW()
);

INSERT INTO pedidos (usuario_id, logradouro, complemento, bairro, cep, total) VALUES
    (1, 'Rua das Flores, 123',    'Apto 42',   'Asa Norte',  '70040-020', 150.00),
    (2, 'Av. Brasil, 456',        'Sala 10',   'Centro',     '01310-100', 89.90),
    (3, 'Rua das Palmeiras, 789', 'Casa',      'Jardins',    '01452-001', 230.00),
    (4, 'Alameda Santos, 1000',   'Bloco B',   'Bela Vista', '01419-002', 45.50),
    (5, 'Rua Augusta, 2000',      'Cobertura', 'Consolação', '01305-100', 599.00);

-- Tabela COM PII CRÍTICO: dados de pagamento
CREATE TABLE pagamentos (
    id              SERIAL PRIMARY KEY,
    pedido_id       INTEGER REFERENCES pedidos(id),
    numero_cartao   VARCHAR(20),        -- PII CRÍTICO: Cartão de crédito (regex)
    titular         VARCHAR(100),       -- PII: Nome (heurística)
    validade        VARCHAR(7),
    tipo            VARCHAR(20),
    created_at      TIMESTAMP DEFAULT NOW()
);

INSERT INTO pagamentos (pedido_id, numero_cartao, titular, validade, tipo) VALUES
    (1, '4111111111111111', 'JOAO SILVA',    '12/2027', 'visa'),
    (2, '5500000000000004', 'MARIA SOUZA',   '06/2026', 'mastercard'),
    (3, '4111111111111111', 'CARLOS P',      '03/2028', 'visa'),
    (4, '5500000000000004', 'ANA LIMA',      '09/2025', 'mastercard'),
    (5, '4111111111111111', 'PEDRO COSTA',   '01/2029', 'visa');

-- Tabela SEM PII: produtos (para validar falsos positivos)
CREATE TABLE produtos (
    id          SERIAL PRIMARY KEY,
    nome        VARCHAR(100),   -- CUIDADO: "nome" é PII por heurística? Aqui é nome de produto!
    descricao   TEXT,
    preco       DECIMAL(10, 2),
    estoque     INTEGER,
    categoria   VARCHAR(50),
    created_at  TIMESTAMP DEFAULT NOW()
);

INSERT INTO produtos (nome, descricao, preco, estoque, categoria) VALUES
    ('Notebook Pro',    'Notebook de alta performance', 4999.00, 10, 'eletrônicos'),
    ('Mouse Wireless',  'Mouse sem fio ergonômico',     149.90,  50, 'periféricos'),
    ('Teclado Mecânico','Teclado com switches blue',    399.00,  25, 'periféricos'),
    ('Monitor 24"',     'Monitor Full HD IPS',          1299.00, 15, 'eletrônicos'),
    ('Headset USB',     'Headset com cancelamento',     299.00,  30, 'periféricos');
