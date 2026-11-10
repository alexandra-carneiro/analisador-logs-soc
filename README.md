# 🛡️ Analisador de Logs para SOC (`analisador-logs-soc`)

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Security Focus](https://img.shields.io/badge/focus-SOC%20%7C%20Blue%20Team-red.svg)
![Dependencies](https://img.shields.io/badge/dependencies-none%20(standard%20library)-green.svg)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux-lightgrey.svg)
![License](https://img.shields.io/badge/license-MIT-informational.svg)

Uma ferramenta prática e leve desenvolvida para analistas de **SOC (Security Operations Center)** e equipas de **Blue Team**. Processa e correlaciona eventos de autenticação de ambientes **Windows** e **Linux (SSH)**, identificando rapidamente anomalias, ataques de dicionário e padrões suspeitos de **força bruta (brute force)**.

---

## 🎯 O Que a Ferramenta Faz

Em operações diárias de SOC e triagem de incidentes (Nível 1 e 2), o tempo de resposta é crítico. Esta ferramenta responde de forma imediata a três perguntas essenciais:

1. 👤 **Quem está a falhar autenticações?** (Top 5 utilizadores mais visados).
2. 🌐 **De onde vêm os ataques?** (Top 5 endereços IP de origem com mais falhas).
3. 🚨 **Existe um ataque de força bruta ativo?** (Correlação temporal em janela deslizante com classificação de gravidade: **Baixo**, **Médio** ou **Alto**).

Além disso, contabiliza os sucessos legítimos e lista detalhadamente as **contas de utilizador bloqueadas** no Active Directory / Windows Server.

---

## ✨ Principais Funcionalidades

- **Deteção Automática de Formato**: identifica o tipo de log pelo conteúdo do ficheiro (sem necessidade de flags adicionais).
- **Suporte Multiplataforma**:
  - **Windows**: ficheiros CSV exportados do Visualizador de Eventos (*Event Viewer* - Segurança).
  - **Linux**: ficheiros de texto do serviço SSH (`/var/log/auth.log` ou `/var/log/secure`).
- **Resiliente e Tolerante a Falhas**: lida com campos em branco, diferentes separadores (vírgula ou ponto e vírgula) e não falha perante ficheiros vazios.
- **Zero Dependências Externas**: construída estritamente com a biblioteca padrão do Python (`csv`, `re`, `datetime`, `collections`).
- **Segurança Operacional**: ferramenta passiva de leitura — não executa comandos no sistema nem envia dados para a rede.
- **Relatório Duplo**: exibe os resultados formatados na consola e guarda automaticamente uma cópia em `relatorio.txt`.

---

## 📋 Resumo das Métricas e Eventos Analisados

| Sistema Operativo | Evento / Padrão | Descrição SOC |
| :--- | :--- | :--- |
| **Windows** | `Event ID 4625` | Falha de Logon (utilizador incorreto ou password errada) |
| **Windows** | `Event ID 4624` | Logon bem-sucedido (controlo volumétrico de acessos) |
| **Windows** | `Event ID 4740` | Conta de utilizador bloqueada (com utilizador e timestamp) |
| **Linux (SSH)** | `Failed password` | Tentativa falhada de login SSH (senhas erradas ou utilizador inválido) |
| **Linux (SSH)** | `Accepted password` | Acesso SSH autorizado com sucesso |
| **Geral (Ambos)**| `5+ falhas em 10 min` | Alerta de Força Bruta por IP (Gravidades: Baixo, Médio, Alto) |

---

## 📥 Como Obter os Ficheiros de Log

### 1. Exportar Logs de Segurança do Windows para CSV
1. Prima as teclas `Win + R`, escreva `eventvwr.msc` e prima `Enter` para abrir o **Visualizador de Eventos**.
2. Na barra lateral esquerda, expanda **Registos do Windows** (*Windows Logs*) e selecione **Segurança** (*Security*).
3. *(Opcional)*: Clique em **Filtrar Registo Atual...** (*Filter Current Log...*) e filtre pelos IDs: `4624, 4625, 4740`.
4. No painel de Ações à direita, clique em **Guardar Todos os Eventos Como...** (ou **Exportar Lista...**).
5. Escolha o tipo de ficheiro **CSV (delimitado por vírgulas) (*.csv)** e guarde o ficheiro na pasta do projeto.

### 2. Copiar o `auth.log` de um Servidor Linux
Em distribuições Debian/Ubuntu, os logs de autenticação ficam em `/var/log/auth.log` (em RHEL/CentOS/Rocky Linux ficam em `/var/log/secure`):
```bash
# 1. No servidor Linux, extraia as linhas do SSH para um ficheiro leve:
sudo grep "sshd" /var/log/auth.log > ~/meu_auth.log

# 2. Na sua máquina local, transfira o ficheiro via scp:
scp utilizador@ip-do-servidor:~/meu_auth.log ./meu_auth.log
```

---

## 🚀 Como Executar

### Pré-requisitos
- Python 3.8 ou superior instalado. Nenhuma instalação via `pip` é necessária.

### Execução via Linha de Comandos
```bash
# Analisar logs do Windows (CSV)
python analisador.py exemplo_windows.csv

# Analisar logs do Linux (auth.log)
python analisador.py exemplo_auth.log
```

### Execução em Modo Interativo
Se executar sem argumentos, o script solicita interativamente o ficheiro:
```bash
python analisador.py
```
```text
--- Analisador de Logs para SOC ---
Introduza o caminho do ficheiro de logs: exemplo_windows.csv
```

---

## 📊 Exemplo de Relatório Gerado

```text
=================================================================
           RELATÓRIO DE ANÁLISE DE LOGS - SOC
=================================================================
Formato detetado: Windows (CSV)
Regra de Força Bruta: 5+ falhas em 10 minutos

1. RESUMO GERAL
-----------------------------------------------------------------
  - Total de logins com falha:   31
  - Total de logins com sucesso: 6
  - Contas bloqueadas:           2

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

4. PADRÕES DE FORÇA BRUTA DETETADOS
-----------------------------------------------------------------
  [ALERTA - Gravidade: ALTO]
    - IP de Origem:        203.0.113.50
    - Falhas na Janela:    21 tentativas em <= 10 minutos
    - Total de Falhas IP:  21
    - Período do Ataque:   10/11/2026 10:10:02 até 10/11/2026 10:14:30
    - Contas Visadas:      administrador

  [ALERTA - Gravidade: BAIXO]
    - IP de Origem:        198.51.100.25
    - Falhas na Janela:    8 tentativas em <= 10 minutos
    - Total de Falhas IP:  8
    - Período do Ataque:   10/11/2026 10:02:15 até 10/11/2026 10:06:15
    - Contas Visadas:      administrator, admin, root, guest, suporte e mais 3 contas

5. DETALHE DE CONTAS BLOQUEADAS (EVENTO 4740)
-----------------------------------------------------------------
  - Conta: administrador        | Hora: 10/11/2026 10:14:35  | Computador: SRV-AD01
  - Conta: financeiro           | Hora: 10/11/2026 10:15:00  | Computador: SRV-AD01

=================================================================
Fim do relatório.
=================================================================

[+] Relatório guardado com sucesso no ficheiro 'relatorio.txt'.
```

---

## 📁 Estrutura do Repositório

```text
├── analisador.py          # Script principal em Python (código limpo, documentado e modular)
├── exemplo_windows.csv    # Dados simulados do Windows (com ataques e bloqueios para teste)
├── exemplo_auth.log       # Dados simulados do Linux (com ataques SSH e logins legítimos)
├── relatorio.txt          # Relatório gerado na última execução
├── COMO-FUNCIONA.md       # Guia didático detalhado para apresentações e defesas técnicas
└── README.md              # Documentação principal do repositório
```

---

## ⚙️ Personalização das Regras

As constantes de deteção encontram-se no início de `analisador.py` e podem ser alteradas facilmente conforme as políticas de segurança da empresa:

```python
LIMITE_FALHAS_BRUTE_FORCE = 5       # Limite mínimo de falhas para acionar o alerta
JANELA_MINUTOS_BRUTE_FORCE = 10     # Intervalo de tempo considerado para a janela deslizante
```

Para uma explicação mais aprofundada de como a janela deslizante funciona e a teoria por detrás de cada ID de evento, consulte o [**`COMO-FUNCIONA.md`**](file:///c:/Users/Ale/Desktop/Project/Dev/python/analisador-logs/COMO-FUNCIONA.md).

---

## 👩‍💻 Autora & Contribuição

Desenvolvido para fins de análise defensiva e automação em segurança da informação. Sugestões e pull requests são bem-vindos!
