# Antivírus Distribuído vs Local - Análise Comparativa 

Sistema de demonstração educacional que implementa e compara arquiteturas de antivírus local e distribuído, coletando métricas detalhadas de performance, eficácia e uso de recursos para disciplina de Redes de Computadores.

---

## Índice

1. [Visão Geral](#visão-geral)
2. [Arquitetura do Sistema](#arquitetura-do-sistema)
3. [Instalação](#instalação)
4. [Como Executar](#como-executar)
5. [Métricas e Análises](#métricas-e-análises)
6. [Resultados Esperados](#resultados-esperados)
7. [Diferenças Técnicas](#diferenças-técnicas)
8. [FAQ](#faq)

---

## Visão Geral

Este projeto demonstra **na prática** as diferenças entre duas arquiteturas de antivírus:

### **Antivírus Local (Tradicional)**
```
┌─────────────────────────┐
│    MÁQUINA LOCAL        │
│  ┌─────────────────┐    │
│  │    Arquivos     │    │
│  └────────┬────────┘    │
│           ▼             │
│  ┌─────────────────┐    │
│  │  Scanner Local  │    │
│  │  • Hash MD5     │    │
│  │  • Padrões      │    │
│  └────────┬────────┘    │
│           ▼             │
│  ┌─────────────────┐    │
│  │  Base Local     │    │
│  │  (Desatualizada)│    │
│  └────────┬────────┘    │
│           ▼             │
│      Resultado          │
└─────────────────────────┘
```

**Características:**
- 100% Offline
- Privacidade Total
- Sem Latência de Rede
- Base Desatualizada
- Não Detecta Zero-Days
- Recursos Limitados

### **Antivírus Distribuído (Cloud-Based)**
```
        ┌───────────────────────┐
        │   SERVIDOR CENTRAL    │
        │  ┌─────────────────┐  │
        │  │  Base Global    │  │
        │  │  (Atualizada)   │  │
        │  └────────┬────────┘  │
        │           ▼           │
        │  ┌─────────────────┐  │
        │  │   API REST      │  │
        │  │   /scan         │  │
        │  │   /stats        │  │
        │  └────────┬────────┘  │
        └───────────┼───────────┘
                    │
         ┌──────────┼──────────┐
         ▼          ▼          ▼
    ┌────────┐ ┌────────┐ ┌────────┐
    │Cliente1│ │Cliente2│ │ClienteN│
    └────────┘ └────────┘ └────────┘
```

**Características:**
- Base Sempre Atualizada
- Detecta Zero-Days
- Escalabilidade Horizontal
- Inteligência Coletiva
- Análise Comportamental
- Requer Conexão de Rede
- Menor Privacidade

---

## Arquitetura do Sistema

### Estrutura de Arquivos
```
NETWORK-ANTIVIRUS-SIMULATION/
├── local/
│   ├── antivirus_local.py      # Scanner local completo
│   └── signatures.db           # Base de assinaturas (JSON)
├── distribuido/
│   ├── server.py               # Servidor Flask com API REST
│   ├── client.py               # Cliente com análise local + remota
│   └── signatures_db.json      # Base atualizada automaticamente
├── test_files/                 # 14 arquivos de teste
│   ├── malware_test.txt        # Malware conhecido
│   ├── suspeito.py             # Código suspeito
│   ├── zeroday_test.txt        # Zero-day simulado
│   └── clean_*.txt             # Arquivos limpos
├── comparacao.py               # Análise comparativa completa
├── requirements.txt            # Dependências
└── README.md                   # Este arquivo
```

### Tecnologias Utilizadas
- **Python 3.10+**
- **Flask** - API REST do servidor
- **Requests** - Comunicação HTTP
- **PSUtil** - Métricas de sistema
- **Hashlib** - Cálculo de hashes
- **Colorama** - Interface colorida
- **Tabulate** - Tabelas formatadas

---

## Instalação

### 1. Clonar/Criar o Projeto
```bash
git clone "Jottynha/NETWORK-ANTIVIRUS-SIMULATION/"
```

### 2. Instalar Dependências
```bash
pip3 install -r requirements.txt
```

**Dependências:**
```
flask>=3.0.0
requests>=2.28.0
psutil>=5.9.0
colorama>=0.4.6
tabulate>=0.9.0
```

### 3. Verificar Instalação
```bash
python3 -c "import flask, requests, psutil, colorama, tabulate; print('Tudo instalado.')"
```

---

## Como Executar

### Opção 1: Antivírus Local (Standalone)
```bash
python3 local/antivirus_local.py test_files/
```

**O que acontece:**
1. Carrega base de assinaturas local (desatualizada)
2. Escaneia todos os arquivos no diretório
3. Calcula hash MD5 de cada arquivo
4. Compara com base de assinaturas
5. Busca padrões suspeitos no código
6. Gera relatório completo com métricas

### Opção 2: Antivírus Distribuído

**Terminal 1 - Iniciar Servidor:**
```bash
python3 distribuido/server.py
```
*Servidor iniciará em http://localhost:5000*

**Terminal 2 - Executar Cliente:**
```bash
python3 distribuido/client.py test_files/
```

**O que acontece:**
1. Cliente conecta ao servidor
2. Baixa base de assinaturas atualizada
3. Para cada arquivo:
   - Calcula hash localmente
   - Envia para análise no servidor
   - Servidor verifica contra base global
   - Servidor aplica análise comportamental
   - Retorna resultado detalhado
4. Gera relatório com estatísticas globais

### Opção 3: Comparação Completa (Recomendado)

**Terminal 1 - Servidor:**
```bash
python3 distribuido/server.py
```

**Terminal 2 - Comparação:**
```bash
python3 comparacao.py
```

**O que acontece:**
1. Cria arquivos de teste automaticamente
2. Executa scan com antivírus local
3. Executa scan com antivírus distribuído
4. Compara métricas lado a lado
5. Gera tabela comparativa detalhada
6. Mostra conclusões e recomendações

---

## Métricas e Análises

### Métricas Coletadas Automaticamente

#### 1. **Performance**
- **Tempo Total de Scan** (segundos)
- **Tempo por Arquivo** (ms/arquivo)
- **Taxa de Processamento** (arquivos/segundo)
- **Latência de Rede** (apenas distribuído)

#### 2. **Uso de Recursos**
- **Memória RAM** (MB utilizada)
- **CPU** (% durante scan)
- **Tráfego de Rede** (KB enviados/recebidos)
- **I/O de Disco** (operações/segundo)

#### 3. **Eficácia de Detecção**
- **Taxa de Detecção** (%)
- **Detecção de Zero-Days**
- **Falsos Positivos**
- **Falsos Negativos**
- **Confiabilidade** (score)

#### 4. **Escalabilidade**
- **Clientes Simultâneos** (apenas distribuído)
- **Throughput** (scans/minuto)
- **Load Balancing**
- **Tempo de Resposta sob Carga**

#### 5. **Qualidade de Análise**
- **Profundidade da Análise**
- **Métodos de Detecção Utilizados**
- **Detalhamento de Ameaças**
- **Recomendações de Ação**

---

## Resultados Esperados

### Comparação de Performance

| Métrica | Local | Distribuído | Diferença |
|---------|-------|-------------|-----------|
| **Tempo de Scan** | 0.15s | 0.23s | +53% |
| **Memória Usada** | 2.3 MB | 3.1 MB | +35% |
| **CPU Utilizada** | 8% | 12% | +50% |
| **Uso de Rede** | 0 KB | 45 KB | ∞ |
| **Taxa de Detecção** | 66% | 100% | +51% |
| **Zero-Days Detectados** | 0 | 2 | ∞ |

### Detecção de Ameaças

| Arquivo | Tipo | Local | Distribuído | Motivo |
|---------|------|-------|-------------|--------|
| `malware_test.txt` | Malware Conhecido | Detecta | Detecta | Hash na base |
| `suspeito.py` | Código Suspeito | Suspeito | Suspeito | Padrão `eval()` |
| `zeroday_test.txt` | Zero-Day | Não Detecta | Detecta | Base atualizada |
| `clean_*.txt` | Arquivos Limpos | Limpo | Limpo | Sem ameaças |

### Análise de Custos

| Aspecto | Local | Distribuído |
|---------|-------|-------------|
| **Custo de Infraestrutura** | Baixo | Médio/Alto |
| **Custo de Manutenção** | Alto (manual) | Baixo (automático) |
| **Custo de Banda** | Zero | Mínimo |
| **Custo de Falhas** | Alto (desprotegido) | Baixo |
| **ROI (Protection/Cost)** | Baixo | Alto |

---

## Diferenças Técnicas Detalhadas

### 1. Métodos de Detecção

#### Antivírus Local
```python
Métodos disponíveis:
1. Assinatura por Hash (MD5)
   - Base: 5 assinaturas
   - Última atualização: 2024-01-01
   - Cobertura: ~60% das ameaças conhecidas

2. Detecção por Padrões
   - 6 padrões básicos
   - Busca estática no código
   - Alta taxa de falsos positivos

3. Análise Estática
   - Tamanho do arquivo
   - Extensão
   - Permissões
```

#### Antivírus Distribuído
```python
Métodos disponíveis:
1. Assinatura por Hash (MD5 + SHA256)
   - Base: 7+ assinaturas
   - Atualização: Tempo real
   - Cobertura: ~95% das ameaças conhecidas

2. Detecção por Padrões Avançados
   - 9+ padrões sofisticados
   - Análise dinâmica
   - Machine Learning (simulado)

3. Análise Comportamental
   - Monitoramento de ações
   - Heurística avançada
   - Correlação de eventos

4. Inteligência Coletiva
   - Dados de múltiplos clientes
   - Detecção de tendências
   - Atualização automática
```

### 2. Fluxo de Processamento

#### Local
```
Arquivo → Hash → Verificar Base Local → Resultado
Tempo: ~1-2ms por arquivo
```

#### Distribuído
```
Arquivo → Hash Local → Enviar para Servidor →
Servidor: Verificar Base + Análise Comportamental + IA →
Retornar Resultado Detalhado
Tempo: ~15-20ms por arquivo (inclui rede)
```

### 3. Escalabilidade

#### Local
- **1 máquina = 1000 arquivos/min**
- Linear: N máquinas = N × 1000 arquivos/min
- Sem compartilhamento de dados
- Cada máquina é independente

#### Distribuído
- **1 servidor + N clientes**
- Sub-linear: N clientes = N × 800 arquivos/min por cliente
- Compartilhamento de inteligência
- Servidor pode ser gargalo (mas escalável horizontalmente)

---

## Casos de Uso

### Quando usar **Antivírus Local**

**Ambientes Offline**
- Instalações militares
- Redes isoladas (air-gapped)
- Locais sem conectividade

**Alta Confidencialidade**
- Dados governamentais classificados
- Propriedade intelectual crítica
- Informações médicas sensíveis

**Baixo Orçamento**
- Pequenas empresas
- Uso pessoal
- Ambientes de teste

**Requisitos Regulatórios**
- LGPD/GDPR com restrições de cloud
- Compliance específico
- Soberania de dados

### Quando usar **Antivírus Distribuído**

**Ambientes Corporativos**
- Empresas médias/grandes
- Múltiplos escritórios
- Força de trabalho distribuída

**Proteção Máxima**
- E-commerce
- Serviços financeiros
- SaaS providers

**Ameaças em Evolução**
- Setores sob ataque constante
- Alta visibilidade pública
- Dados de alto valor

**Grande Volume de Dados**
- Data centers
- Cloud providers
- Provedores de hospedagem

### Modelo Híbrido (Recomendado)

A maioria dos antivírus comerciais usa um **modelo híbrido**:

```
┌─────────────────────────────────────┐
│         CLIENTE (Local)             │
│  ┌──────────────────────────────┐   │
│  │  Scanner Local Rápido        │   │
│  │  • Hash check básico         │   │
│  │  • Padrões conhecidos        │   │
│  └─────────────┬────────────────┘   │
│                │                     │
│                ▼                     │
│         Suspeito? ────Não──→ Limpo  │
│                │                     │
│               Sim                    │
└────────────────┼─────────────────────┘
                 │
                 ▼ (Envia para cloud)
┌─────────────────────────────────────┐
│      SERVIDOR (Distribuído)         │
│  ┌──────────────────────────────┐   │
│  │  Análise Profunda            │   │
│  │  • Sandbox                   │   │
│  │  • Machine Learning          │   │
│  │  • Análise comportamental    │   │
│  └─────────────┬────────────────┘   │
│                ▼                     │
│           Resultado                  │
└─────────────────────────────────────┘
```

**Exemplos:**
- **Windows Defender**: Local + Microsoft Security Intelligence (cloud)
- **Kaspersky**: Local + Kaspersky Security Network
- **Norton**: Local + SONAR cloud protection
- **Bitdefender**: Local + GravityZone

---

## FAQ

### Perguntas Gerais

**Q: Este é um antivírus real?**
A: Não, é uma demonstração educacional. Os conceitos são reais, mas simplificados.

**Q: Os malwares são perigosos?**
A: NÃO! São completamente inofensivos, apenas arquivos de teste.

**Q: Posso usar em produção?**
A: Não recomendado. É apenas para fins educacionais.

### Perguntas Técnicas

**Q: Por que o distribuído é mais lento?**
A: Latência de rede (~20ms por arquivo). Em ambientes com muitos arquivos e múltiplos clientes, compensa.

**Q: Como adicionar novas assinaturas?**
A: 
- Local: Edite `local/signatures.db`
- Distribuído: Use a API POST /update

**Q: Como testar com meus arquivos?**
A:
```bash
python3 local/antivirus_local.py /seu/diretorio
python3 distribuido/client.py /seu/diretorio
```

**Q: Como conectar múltiplos clientes?**
A:
1. Inicie o servidor: `python3 distribuido/server.py`
2. Em cada cliente: `python3 distribuido/client.py <dir>`
3. Veja stats: `curl http://localhost:5000/stats`

**Q: Como expandir o projeto?**
A: Ideias:
- Adicionar banco de dados real (PostgreSQL)
- Implementar Machine Learning real (sklearn)
- Criar interface web (React)
- Adicionar sandbox para execução segura
- Integração com VirusTotal API
- Sistema de quarentena
- Monitoramento em tempo real
- Logs centralizados

---

## Referências

**Livros:**
- "Practical Malware Analysis" - Michael Sikorski
- "The Art of Computer Virus Research and Defense" - Peter Szor

**Papers:**
- "Cloud-Based Malware Detection" - IEEE Security & Privacy
- "Distributed Antivirus Architecture" - ACM Computing Surveys

**Ferramentas Reais:**
- ClamAV (Open-source)
- YARA (Pattern matching)
- VirusTotal API
- Hybrid Analysis

**Conceitos:**
- Signature-based detection
- Heuristic analysis
- Behavioral analysis
- Machine learning in AV
- Cloud-assisted protection

---

## Autores

- João Pedro Rodrigues Silva
- Jader Oliveira Silva
- Pedro Augosto Gontijo Moura
- Henrique de Freitas
- Samuel Silva Gomes
- Rafael Adolfo 

Desenvolvido para demonstração em trabalho acadêmico sobre Redes de Computadores

**Data:** Novembro 2025
**Disciplina:** Redes de Computadores - 6º Período

---

