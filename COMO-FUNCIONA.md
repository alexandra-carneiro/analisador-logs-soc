# Como Funciona o analisador-logs-soc

Este documento explica, em **linguagem simples e direta**, o funcionamento interno da ferramenta, a lógica usada para identificar ataques e o significado de cada evento de segurança do Windows e do Linux.

Foi desenhado para que qualquer pessoa consiga compreender e apresentar a ferramenta com confiança, mesmo sem experiência avançada em cibersegurança ou programação.

---

## 1. O que é um Ataque de Força Bruta (Brute Force)?

Um ataque de força bruta é uma técnica usada por atacantes ou ferramentas automatizadas (bots) que tentam adivinhar credenciais de acesso experimentando repetidamente combinações de utilizadores e palavras-passe até encontrarem uma que funcione.

Geralmente, um ser humano que se engana na palavra-passe faz 1 ou 2 tentativas e depois acerta ou pede a recuperação de conta. Em contrapartida, um ataque automatizado caracteriza-se por:
- **Grande quantidade de tentativas** falhadas.
- **Origem no mesmo endereço IP**.
- **Espaço de tempo muito curto** (segundos ou poucos minutos).
- **Alvos genéricos** (como `admin`, `root`, `suporte`, `gestor`, `administrator`).

---

## 2. Como a Ferramenta Deteta Força Bruta?

A ferramenta utiliza uma técnica comum na indústria de SOC chamada **janela temporal deslizante** (sliding time window):

1. **Agrupamento por IP de Origem**: todas as falhas de login registadas são associadas ao endereço IP de onde vieram.
2. **Avaliação Temporal**: para cada IP, a ferramenta organiza os registos por ordem cronológica.
3. **Cálculo da Janela de 10 minutos**: o algoritmo percorre cada falha e verifica quantas tentativas adicionais aquele IP fez nos 10 minutos seguintes.
4. **Disparo do Alerta**: se forem encontradas **5 ou mais falhas** dentro de qualquer intervalo de até 10 minutos, a ferramenta gera um alerta de segurança.

### Escala de Gravidade

Para ajudar o analista a priorizar o incidente, a ferramenta classifica cada padrão detetado em três níveis de gravidade:

- **Gravidade BAIXO (5 a 9 falhas em 10 min)**: Pode ser um utilizador legítimo que se esqueceu da palavra-passe ou um script interno mal configurado, mas justifica verificação.
- **Médio (10 a 19 falhas em 10 min)**: Padrão claro de adivinhação insistente de credenciais.
- **ALTO (20 ou mais falhas em 10 min)**: Ataque automatizado em massa (dicionário ou botnet), com elevada probabilidade de tentar bloquear contas ou comprometer o sistema.

### Como Mudar os Limites no Código

As regras de deteção estão no topo do ficheiro `analisador.py` em constantes simples:
```python
LIMITE_FALHAS_BRUTE_FORCE = 5       # Número mínimo de falhas para alertar
JANELA_MINUTOS_BRUTE_FORCE = 10     # Intervalo de tempo em minutos
```
Se a política da sua organização considerar força bruta apenas a partir de 10 tentativas em 5 minutos, basta alterar estes dois números no código.

---

## 3. Eventos do Windows (Logs de Segurança)

No Windows, os eventos de auditoria são identificados por códigos numéricos chamados **Event IDs**. A ferramenta analisa os três IDs essenciais para a deteção de intrusões em acessos:

### ID 4624 — Logon com Sucesso
- **O que significa**: Um utilizador ou serviço autenticou-se com sucesso na máquina ou no domínio Active Directory.
- **Por que é importante no SOC**: Permite ter a contagem total de acessos legítimos. Quando ocorre um pico de falhas seguido de um evento 4624 do mesmo IP, isso indica que o atacante pode ter tido sucesso e que a conta foi comprometida.

### ID 4625 — Logon com Falha
- **O que significa**: Houve uma tentativa de entrada no sistema que foi recusada (por exemplo, palavra-passe incorreta, nome de utilizador inexistente ou conta desativada).
- **Por que é importante no SOC**: É o principal indicador de problemas de autenticação e ataques de força bruta. A ferramenta extrai deste evento o nome do utilizador visado, o endereço IP de onde veio o pedido e a data/hora exata.

### ID 4740 — Conta de Utilizador Bloqueada
- **O que significa**: A conta de um utilizador foi bloqueada pelo sistema porque excedeu o número máximo de tentativas de login incorretas permitido pela política de segurança da empresa (Account Lockout Policy).
- **Por que é importante no SOC**: Mostra o impacto real do ataque na organização. Uma conta bloqueada pode causar indisponibilidade de trabalho a um colaborador ou indicar que o atacante ativou as proteções do sistema. A ferramenta lista quem foi bloqueado e a hora exata do evento.

---

## 4. Mensagens do Linux (`auth.log` / `secure`)

No Linux, o serviço que gere as ligações remotas por terminal é o **OpenSSH (`sshd`)**. As suas mensagens de autenticação são registadas em texto corrido:

### "Failed password for..."
- **O que significa**: Alguém tentou ligar-se por SSH e a palavra-passe introduzida estava errada, ou a conta nem sequer existe no sistema (surge frequentemente com o prefixo `Failed password for invalid user <nome>`).
- **Exemplo**:
  ```text
  Nov 10 11:00:10 srv-linux sshd[2110]: Failed password for invalid user admin from 198.51.100.77 port 41201 ssh2
  ```
- **Por que é importante no SOC**: É o equivalente direto do evento 4625 do Windows. Permite saber que utilizadores estão a ser visados e que endereços IP na Internet ou na rede interna estão a tentar invadir o servidor.

### "Accepted password for..."
- **O que significa**: A ligação por SSH foi autorizada e o utilizador iniciou sessão com sucesso usando a sua palavra-passe.
- **Exemplo**:
  ```text
  Nov 10 10:50:12 srv-linux sshd[2101]: Accepted password for joao from 192.168.1.50 port 52314 ssh2
  ```
- **Por que é importante no SOC**: É o equivalente ao evento 4624 do Windows. Garante visibilidade sobre o total de acessos autorizados ao sistema.

---

## 5. Deteção Automática do Formato

A ferramenta lê as primeiras linhas do ficheiro e toma decisões com base no seu conteúdo:
1. **Verificação de Vazio**: se o ficheiro estiver vazio, termina de imediato com um aviso amigável, sem erros ou falhas.
2. **Linux**: procura por palavras-chave do serviço SSH (`sshd`, `failed password`, `accepted password`).
3. **Windows**: procura por termos e cabeçalhos habituais do Visualizador de Eventos (`id do evento`, `event id`, `4625`, `4624`, `4740`, ou delimitadores de colunas CSV).

Desta forma, o analista do SOC só precisa de indicar o nome do ficheiro, e a ferramenta adapta-se automaticamente.
