# 🛡️ Analisador de Logs para SOC (`analisador-logs-soc`)

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Security Focus](https://img.shields.io/badge/focus-SOC%20%7C%20Blue%20Team-red.svg)
![Threat Detection](https://img.shields.io/badge/detection-Brute%20Force%20%7C%20Password%20Spraying-darkred.svg)
![Reports](https://img.shields.io/badge/reports-Terminal%20%7C%20TXT%20%7C%20PDF%20%7C%20JSON-success.svg)
![AI-Assisted](https://img.shields.io/badge/developed%20with-Google%20Antigravity%20%26%20Gemini-8E75C4.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-informational.svg)

Uma ferramenta prática, robusta e leve desenvolvida para analistas de **SOC (Security Operations Center)** e equipas de **Blue Team**. Processa e correlaciona eventos de autenticação de ambientes **Windows** e **Linux (SSH)**, identificando anomalias, ataques de dicionário, **força bruta (brute force)**, **password spraying**, persistência, elevação de privilégios e acessos fora de horas.

---

## 🎯 O Que a Ferramenta Faz

Em operações diárias de SOC e triagem de incidentes (Nível 1 e 2), o tempo de resposta é crítico. Esta ferramenta responde de forma imediata a cinco perguntas essenciais:

1. 👤 **Quem está a falhar autenticações?** (Top 5 utilizadores mais visados).
2. 🌐 **De onde vêm os ataques?** (Top 5 endereços IP de origem com mais falhas).
3. 🚨 **Existe força bruta ativa?** (Ataques verticais concentrados na mesma conta).
4. 🌊 **Existe password spraying ativo?** (Ataques horizontais tentando poucas senhas em muitas contas diferentes para burlar regras de bloqueio).
5. 🕵️ **Há indícios de invasão ou persistência?** (Contas criadas, adições a grupos privilegiados, superdireitos ou logins de madrugada).

Além disso, contabiliza os acessos autorizados e lista detalhadamente as **contas de utilizador bloqueadas** no Active Directory / Windows Server.

---

## ✨ Principais Funcionalidades

- **Deteção Automática de Formato**: identifica o tipo de log pelo conteúdo do ficheiro (sem flags manuais obrigatórias).
- **Motores de Deteção Inteligente (Python Puro)**:
  - **Força Bruta Concentrada**: janela deslizante que identifica rajadas de tentativas repetidas contra a mesma conta.
  - **Password Spraying**: análise de dispersão que identifica quando um mesmo IP ataca 4 ou mais contas distintas com poucas tentativas por conta.
  - **Logons Fora de Horas**: identificação de acessos bem-sucedidos fora do expediente comercial ou em fins de semana.
  - **Auditoria de Privilégios no Windows**: deteção de contas criadas (4720), elevação de grupos (4728) e privilégios especiais (4672).
- **Arquitetura Híbrida de Performance (Dual-Engine)**:
  - Motor leve nativo para o dia a dia (sem dependências externas pesadas).
  - Aceleração vetorial com **Pandas** ativada automaticamente para logs volumosos (>50MB) ou via flag `--pandas`.
- **Enriquecimento com Threat Intelligence (AbuseIPDB)**:
  - Consulta automática à API gratuita da AbuseIPDB filtrando apenas IPs públicos de Internet, trazendo pontuação de maliciosidade (*Abuse Score*), país e ISP.
- **Análise Assistida por Inteligência Artificial (Google Gemini)**:
  - O Gemini atua como Analista de SOC Nível 3 (L3), fornecendo diagnóstico claro da ameaça, impacto e plano de ação imediato para contenção.
- **Resiliente e Tolerante a Falhas**: lida com campos em branco, diferentes separadores (vírgula ou ponto e vírgula) e trata ficheiros vazios sem crashar.
- **Relatório Executivo Multi-formato**:
  - 🖥️ **Terminal**: exibição formatada e legível no console.
  - 📄 **Texto (`relatorio.txt`)**: saída em texto simples para auditoria ou scripts.
  - 📊 **PDF Executivo (`relatorio.pdf`)**: gerado com `fpdf2`, com cabeçalho de SOC, tabelas de métricas e alertas coloridos por nível de gravidade (**Vermelho** para Alto, **Laranja** para Médio e **Azul** para Baixo).
  - 🔌 **JSON Estruturado (`relatorio.json`)**: formato padronizado com esquema interoperável para ingestão por SIEMs (Splunk, Elastic, Microsoft Sentinel) e automações SOAR.

---

## 🔍 Lógica de Deteção e Fundamentos Teóricos (SOC)

### 1. Dois Vetores de Ataque: Força Bruta vs. Password Spraying

Para analistas de segurança defensiva, é crucial distinguir a mecânica de cada ataque:

| Característica | Força Bruta Tradicional (Brute Force) | Password Spraying (Dispersão Horizontal) |
| :--- | :--- | :--- |
| **Direção do Ataque** | **Vertical** (profundidade) | **Horizontal** (largura) |
| **Alvo** | 1 conta específica (ex.: `administrador`) | Dezenas ou centenas de contas diferentes |
| **Tentativas por Conta**| Dezenas ou centenas na mesma conta | Apenas 1 ou 2 tentativas por conta |
| **Objetivo do Atacante**| Quebrar a senha daquela conta a todo o custo | **Evitar o bloqueio de contas** e testar senhas corporativas comuns |
| **Exemplo Típico** | Testar 1000 senhas para o utilizador `root` | Testar a senha `Empresa2026!` em 50 colaboradores |

### 2. Deteção de Força Bruta (Janela Temporal Deslizante)
A ferramenta implementa um algoritmo de **sliding window**:
1. **Agrupamento por IP**: todas as falhas de autenticação são associadas ao endereço IP de origem.
2. **Ordenação Cronológica**: os eventos são ordenados no tempo para cada IP.
3. **Janela Deslizante de 10 minutos**: a ferramenta calcula o maior pico de falhas registadas em qualquer intervalo contínuo de até 10 minutos.
4. **Classificação de Gravidade**:
   - **BAIXO**: 5 a 9 falhas em $\le$ 10 minutos (pode ser utilizador distraído ou scan superficial).
   - **MÉDIO**: 10 a 19 falhas em $\le$ 10 minutos (tentativa coordenada de adivinhação).
   - **ALTO**: 20 ou mais falhas em $\le$ 10 minutos (ataque automatizado massivo com dicionário).

### 3. Deteção de Password Spraying (Análise de Dispersão)
Para identificar atacantes que contornam as políticas de bloqueio de conta (*Account Lockout*):
1. **Contagem de Contas Distintas**: contabiliza quantos utilizadores diferentes foram visados pelo mesmo IP.
2. **Cálculo da Média de Tentativas por Conta**:
   $$\text{Média por Conta} = \frac{\text{Total de Falhas na Janela}}{\text{Número de Contas Distintas}}$$
3. **Regra de Alerta**: se o IP atacou **$\ge 4$ contas distintas** com **média $\le 3$ tentativas por conta**, o evento é categorizado como *Password Spraying*.
   - **BAIXO**: 4 a 6 contas distintas.
   - **MÉDIO**: 7 a 14 contas distintas.
   - **ALTO**: 15 ou mais contas distintas.

### 4. Deteção de Logons Fora de Horas
Logons bem-sucedidos de madrugada ou em fins de semana representam potenciais anomalias operacionais (invasor agindo enquanto a equipa de TI está ausente ou exfiltração de dados).
- Horário comercial padrão: `08:00` às `19:00` (configurável).
- Fins de semana: Sábados e Domingos são marcados como fora de horas.

### 5. Significado dos Event IDs do Windows
- **`4624` (Logon com Sucesso)**: controlo volumétrico de acessos normais. Se um pico de falhas for seguido por um 4624 do mesmo IP, a conta pode ter sido comprometida.
- **`4625` (Logon com Falha)**: evento fundamental para alimentar os motores de Força Bruta e Password Spraying.
- **`4740` (Conta Bloqueada)**: indica impacto operacional e ativação da política de bloqueio (*Account Lockout*).
- **`4720` (Conta Criada)**: indicador crítico de persistência (*backdoor account*) após invasão de servidor.
- **`4728` (Membro Adicionado a Grupo de Segurança)**: alerta de altíssima severidade indicando elevação de privilégios (*Privilege Escalation*).
- **`4672` (Privilégios Especiais Atribuídos)**: logon exercendo direitos administrativos máximos (`SeDebugPrivilege`, `SeTakeOwnershipPrivilege`).

### 6. Significado dos Logs do Linux OpenSSH
- **`Failed password for...`**: tentativa falhada de login SSH (equivalente ao 4625 do Windows).
- **`Accepted password for...`**: sessão SSH autenticada com sucesso (equivalente ao 4624 do Windows).

### 7. Arquitetura Híbrida (Dual-Engine: Nativo vs. Pandas)
- **Motor Leve (Python Standard Library)**: padrão para uso quotidiano, sem necessidade de pacotes pesados ou compiladores C.
- **Motor Acelerado (Pandas)**: ativado automaticamente para ficheiros superiores a **50 MB** ou via flag `--pandas`, aproveitando operações vetorizadas para processar milhões de linhas em segundos.

---

## 📋 Tabela Resumo de Métricas e Eventos

| Sistema Operativo | Evento / Padrão | Classificação SOC |
| :--- | :--- | :--- |
| **Windows** | `Event ID 4625` | Falha de Logon (utilizador incorreto ou senha errada) |
| **Windows** | `Event ID 4624` | Logon bem-sucedido (controlo volumétrico e acessos fora de horas) |
| **Windows** | `Event ID 4740` | Conta de utilizador bloqueada (com utilizador, hora e computador) |
| **Windows** | `Event ID 4720` | Conta criada (indicador crítico de persistência / backdoor) |
| **Windows** | `Event ID 4728` | Membro adicionado a grupo priv. (elevação de privilégios) |
| **Windows** | `Event ID 4672` | Logon com privilégios especiais (superadministrador) |
| **Linux (SSH)** | `Failed password` | Tentativa falhada de login SSH (senhas erradas ou utilizador inválido) |
| **Linux (SSH)** | `Accepted password` | Acesso SSH autorizado com sucesso |
| **Geral (Ambos)**| `5+ falhas em 10 min` | **Força Bruta**: ataque concentrado/vertical (Baixo, Médio, Alto) |
| **Geral (Ambos)**| `4+ contas (<=3 tent/conta)` | **Password Spraying**: ataque horizontal/disperso (Baixo, Médio, Alto) |

---

## 📥 Como Obter os Ficheiros de Log

### 1. Exportar Logs de Segurança do Windows para CSV
1. Prima as teclas `Win + R`, escreva `eventvwr.msc` e prima `Enter` para abrir o **Visualizador de Eventos**.
2. Na barra lateral esquerda, expanda **Registos do Windows** (*Windows Logs*) e selecione **Segurança** (*Security*).
3. *(Opcional)*: Clique em **Filtrar Registo Atual...** (*Filter Current Log...*) e filtre pelos IDs desejados (`4624, 4625, 4740, 4720, 4728, 4672`).
4. No painel de Ações à direita, clique em **Guardar Todos os Eventos Como...** (ou **Exportar Lista...**).
5. Escolha o formato **CSV (delimitado por vírgulas) (*.csv)**.

### 2. Copiar o `auth.log` de um Servidor Linux
Em distribuições Debian/Ubuntu, os logs de autenticação ficam em `/var/log/auth.log` (em RHEL/CentOS/Rocky Linux ficam em `/var/log/secure`):
```bash
# 1. No servidor Linux, filtre as linhas do SSH para um ficheiro leve:
sudo grep "sshd" /var/log/auth.log > ~/meu_auth.log

# 2. Na sua estação de trabalho, transfira o ficheiro via scp:
scp utilizador@ip-do-servidor:~/meu_auth.log ./meu_auth.log
```

---

## 🚀 Como Executar

### 1. Instalação de Dependências Opcionais
```bash
pip install -r requirements.txt
```
*(Nota: a ferramenta funciona 100% com a biblioteca padrão do Python. Apenas `fpdf2` e `requests` são necessários para PDF e Threat Intel).*

### 2. Execução via Linha de Comandos
```bash
# Analisar logs do Windows (CSV)
python analisador.py exemplo_windows.csv

# Analisar logs do Linux (auth.log)
python analisador.py exemplo_auth.log

# Forçar aceleração com Pandas (se instalado)
python analisador.py exemplo_windows.csv --pandas
```

### 3. Modo Interativo
Se nenhum argumento for passado, a ferramenta solicita o caminho do ficheiro na consola:
```bash
python analisador.py
```

### 4. Configuração Opcional de APIs Externas
Copie o ficheiro `.env.example` para `.env` e configure as suas chaves gratuitas:
```bash
# Ativar Threat Intelligence (AbuseIPDB):
ABUSEIPDB_API_KEY=sua_chave_aqui

# Ativar Parecer Técnico de SOC por IA (Google Gemini):
GEMINI_API_KEY=sua_chave_aqui
```

---

## 📊 Exemplo de Saída no Terminal

```text
=================================================================
           RELATÓRIO DE ANÁLISE DE LOGS - SOC
=================================================================
Formato detetado: Windows (CSV)
Regras de Deteção: Brute Force (5+ falhas/10m) | Password Spraying (4+ contas/30m)

1. RESUMO GERAL
-----------------------------------------------------------------
  - Total de logins com falha:   31
  - Total de logins com sucesso: 7
  - Contas bloqueadas (4740):    2
  - Logons fora de horas:        1
  - Contas criadas (4720):       1
  - Adições a grupos priv. (4728):1
  - Logons privilegiados (4672):  1

2. TOP 5 UTILIZADORES COM MAIS FALHAS
-----------------------------------------------------------------
  1. Utilizador: administrador             | Falhas: 21
  2. Utilizador: carlos                    | Falhas: 2
  3. Utilizador: administrator             | Falhas: 1
  4. Utilizador: admin                     | Falhas: 1
  5. Utilizador: root                      | Falhas: 1

3. TOP 5 IPs DE ORIGEM COM MAIS FALHAS
-----------------------------------------------------------------
  1. IP: 203.0.113.50                      | Falhas: 21
  2. IP: 198.51.100.25                     | Falhas: 8
  3. IP: 192.168.1.45                      | Falhas: 2

4. PADRÕES DE FORÇA BRUTA (ATAQUE VERTICAL / CONCENTRADO)
-----------------------------------------------------------------
  [ALERTA - Gravidade: ALTO]
    - IP de Origem:        203.0.113.50
    - Falhas na Janela:    21 tentativas em <= 10 minutos
    - Total de Falhas IP:  21
    - Período do Ataque:   10/11/2026 10:10:02 até 10/11/2026 10:14:30
    - Contas Visadas:      administrador

5. PADRÕES DE PASSWORD SPRAYING (DISPERSÃO DE CONTAS)
-----------------------------------------------------------------
  [ALERTA - Gravidade: MÉDIO]
    - IP de Origem:        198.51.100.25
    - Contas Distintas:    8 contas visadas
    - Média por Conta:     1.0 tentativas (spray horizontal)
    - Total de Tentativas: 8
    - Período do Ataque:   10/11/2026 10:02:15 até 10/11/2026 10:06:15
    - Contas Visadas:      administrator, admin, root, guest, suporte, backup e mais 2 contas

6. DETALHE DE CONTAS BLOQUEADAS (EVENTO 4740)
-----------------------------------------------------------------
  - Conta: administrador        | Hora: 10/11/2026 10:14:35  | Computador: SRV-AD01
  - Conta: financeiro           | Hora: 10/11/2026 10:15:00  | Computador: SRV-AD01

7. PERSISTÊNCIA E PRIVILÉGIOS (EVENTOS 4720, 4728, 4672)
-----------------------------------------------------------------
  [!] CONTAS DE UTILIZADOR CRIADAS (ID 4720 - Indicador de Persistência):
    - Conta Criada: svc_temp_backdoor    | Hora: 10/11/2026 10:17:15  | Computador: SRV-AD01

  [!] ADIÇÕES A GRUPOS PRIVILEGIADOS (ID 4728 - Elevação de Privilégios):
    - Membro:       svc_temp_backdoor    | Hora: 10/11/2026 10:17:40  | Computador: SRV-AD01

  [!] LOGONS COM SUPERPRIVILÉGIOS (ID 4672 - Administrador Especial):
    - Conta:        svc_temp_backdoor    | Hora: 10/11/2026 10:18:05  | Computador: SRV-AD01

=================================================================
Fim do relatório.
=================================================================
[+] Relatório em texto guardado em 'relatorio.txt'.
[+] Relatório estruturado em JSON guardado em 'relatorio.json'.
[+] Relatório executivo em PDF guardado com sucesso em 'relatorio.pdf'.
```

---

## 🗺️ Roadmap de Evolução

Todas as melhorias planeadas para o projeto foram 100% implementadas:

- [x] **1. Relatório em PDF com o `fpdf2`**: cabeçalho executivo de SOC, tabelas de métricas e alertas coloridos por gravidade.
- [x] **2. Deteção de *Password Spraying***: identificação de contas diferentes atacadas pelo mesmo IP com poucas tentativas por conta.
- [x] **3. Novos Event IDs de Auditoria Windows**: deteção de criação de conta (4720), adição a grupos privilegiados (4728) e superdireitos (4672).
- [x] **4. Logons Fora de Horas**: identificação de acessos autorizados fora do expediente habitual ou ao fim de semana.
- [x] **5. Exportação em JSON (`relatorio.json`)**: esquema estruturado padronizado para ingestão em SIEM/SOAR.
- [x] **6. Enriquecimento com AbuseIPDB**: consulta automatizada à API gratuita para análise de reputação e histórico de denúncias.
- [x] **7. Explicação por IA com Google Gemini**: resumo automático, diagnóstico e plano de ação imediato gerado pelo modelo Gemini.
- [x] **8. Otimização com Pandas (Dual-Engine)**: aceleração vetorial automática para ficheiros volumosos (>50MB).

---

## 📁 Estrutura do Repositório

```text
analisador-logs-soc/
├── analisador.py          # Motor principal (análise, correlação, console, TXT, PDF e JSON)
├── exemplo_windows.csv    # Dataset simulado com cenários de Brute Force, Spraying e Persistência
├── exemplo_auth.log       # Dataset simulado com ataques OpenSSH e acessos fora de horas
├── requirements.txt       # Dependências opcionais (fpdf2, requests e menção ao pandas)
├── .env.example           # Modelo seguro para configuração das chaves de API opcionais
├── .gitignore             # Ignora ambientes virtuais, ficheiros temporários e relatórios gerados
└── README.md              # Documentação oficial completa e guia operacional de SOC
```

*(Nota: os ficheiros de relatório `relatorio.txt`, `relatorio.pdf` e `relatorio.json` são gerados dinamicamente em tempo de execução e mantidos fora do controlo de versão por boas práticas).*

---

## ⚙️ Configuração de Regras

As constantes de deteção encontram-se no topo de `analisador.py`:
```python
# Força Bruta Tradicional (Vertical)
LIMITE_FALHAS_BRUTE_FORCE = 5       # Limite mínimo de falhas para acionar o alerta
JANELA_MINUTOS_BRUTE_FORCE = 10     # Intervalo de tempo para a janela deslizante

# Password Spraying (Horizontal)
LIMITE_CONTAS_PASSWORD_SPRAYING = 4        # Mínimo de contas distintas visadas
MAX_TENTATIVAS_POR_CONTA_SPRAYING = 3      # Média máxima de tentativas por conta
JANELA_MINUTOS_PASSWORD_SPRAYING = 30      # Janela temporal do ataque de spray

# Horário Comercial e Fora de Horas
HORARIO_INICIO_EXPEDIENTE = 8              # 08:00
HORARIO_FIM_EXPEDIENTE = 19                # 19:00
CONSIDERAR_FIM_DE_SEMANA_FORA_DE_HORAS = True
```

---

## 🤖 Desenvolvimento com Inteligência Artificial

Este projeto foi concebido e construído em regime de **pair programming com agentes de Inteligência Artificial**, aliando os requisitos práticos de operações de segurança defensiva (SOC/Blue Team) à automação de software de ponta:

- **Google Antigravity**: Ambiente e agente avançado de engenharia de software da equipa do **Google DeepMind**, responsável pela orquestração do ciclo de vida do projeto, execução e validação contínua de testes, gestão de branches e automação de repositório no GitHub.
- **Modelos Gemini (Google DeepMind)**:
  - Modelação da lógica matemática de correlação temporal por janela deslizante para deteção de força bruta.
  - Modelação do algoritmo de dispersão de contas para identificação precisa de *Password Spraying*.
  - Arquitetura de código defensivo em Python puro (suporte a múltiplas codificações de texto, tolerância a dados parciais e prevenção de falhas).
  - Desenho do gerador de relatórios executivos em PDF com a biblioteca `fpdf2`.
  - Elaboração dos datasets de teste sintéticos reproduzindo ataques reais do Active Directory e OpenSSH.

---

## 👩‍💻 Autora & Contribuição

Desenvolvido por **Alexandra Carneiro** para operações de triagem defensiva, cibersegurança e resposta a incidentes. Contribuições, melhorias e sugestões são bem-vindas!
