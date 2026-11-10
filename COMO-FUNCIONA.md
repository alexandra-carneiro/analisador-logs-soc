# Como Funciona o analisador-logs-soc

Este documento explica, em **linguagem simples e direta**, o funcionamento interno da ferramenta, a lógica usada para identificar ataques e o significado de cada evento de segurança do Windows e do Linux.

Foi desenhado para que qualquer pessoa consiga compreender e apresentar a ferramenta com confiança, mesmo sem experiência avançada em cibersegurança ou programação.

---

## 1. Dois Vetores de Ataque: Força Bruta vs. Password Spraying

Para quem trabalha num SOC (Security Operations Center), é fundamental distinguir estes dois tipos de ataques de autenticação:

| Característica | Força Bruta Tradicional (Brute Force) | Password Spraying (Dispersão Horizontal) |
| :--- | :--- | :--- |
| **Direção do Ataque** | **Vertical** (profundidade) | **Horizontal** (largura) |
| **Alvo** | 1 conta específica (ex.: `admin`) | Dezenas ou centenas de contas diferentes |
| **Tentativas por Conta** | Dezenas ou centenas na mesma conta | Apenas 1 ou 2 tentativas por conta |
| **Objetivo do Atacante** | Quebrar a senha daquela conta a todo o custo | **Evitar o bloqueio de contas** e adivinhar senhas comuns da empresa |
| **Exemplo Típico** | Testar 1000 senhas para o utilizador `root` | Testar a senha `Primavera2026!` em 50 funcionários diferentes |

---

## 2. Como a Ferramenta Deteta Força Bruta (Brute Force)?

A ferramenta utiliza o algoritmo de **janela temporal deslizante** (*sliding window*):

1. **Agrupamento por IP de Origem**: todas as falhas de login registadas são associadas ao endereço IP de onde vieram.
2. **Avaliação Temporal**: para cada IP, a ferramenta organiza os registos por ordem cronológica.
3. **Cálculo da Janela de 10 minutos**: o algoritmo percorre cada falha e verifica quantas tentativas aquele IP fez nos 10 minutos seguintes.
4. **Disparo do Alerta**: se forem encontradas **5 ou mais falhas** dentro de qualquer intervalo de até 10 minutos focadas em poucas contas, a ferramenta gera um alerta de força bruta concentrada.

### Escala de Gravidade do Brute Force
- **BAIXO (5 a 9 falhas em 10 min)**: Pode ser um utilizador distraído ou scan superficial.
- **MÉDIO (10 a 19 falhas em 10 min)**: Tentativa coordenada de adivinhação.
- **ALTO (20 ou mais falhas em 10 min)**: Ataque automatizado massivo (dicionário).

---

## 3. Como a Ferramenta Deteta Password Spraying?

Para apanhar ataques inteligentes que tentam contornar regras de bloqueio testando poucas senhas por conta, a ferramenta aplica uma análise de dispersão:

1. **Contagem de Contas Únicas**: para cada IP com falhas, a ferramenta conta quantos utilizadores distintos foram atacados.
2. **Cálculo da Média de Tentativas por Conta**:
   $$\text{Média por Conta} = \frac{\text{Total de Tentativas}}{\text{Número de Contas Únicas}}$$
3. **Regra de Detecção**:
   - Se o IP atacou **4 ou mais contas diferentes** (`LIMITE_CONTAS_PASSWORD_SPRAYING = 4`).
   - E a média de tentativas por conta for **baixa (≤ 3 tentativas por conta)** (`MAX_TENTATIVAS_POR_CONTA_SPRAYING = 3`).
   - A ferramenta classifica o incidente como **Password Spraying**, isolando-o de falsos positivos.

### Escala de Gravidade do Password Spraying
- **BAIXO**: 4 a 6 contas distintas visadas.
- **MÉDIO**: 7 a 14 contas distintas visadas.
- **ALTO**: 15 ou mais contas distintas visadas.

---

## 4. Deteção de Logons Fora de Horas (Horário Não Comercial)

No dia a dia de um SOC, logins bem-sucedidos que ocorrem de madrugada ou ao fim de semana são fortes candidatos a atividade anómala (ex.: colaboradores a trabalhar em horários incomuns ou invasores a agir quando a equipa de TI está ausente).

A ferramenta permite configurar o horário de expediente da organização:
```python
HORARIO_INICIO_EXPEDIENTE = 8                     # 08:00
HORARIO_FIM_EXPEDIENTE = 19                       # 19:00
CONSIDERAR_FIM_DE_SEMANA_FORA_DE_HORAS = True     # Sábados e Domingos
```
Quando um evento de logon com sucesso (**4624** no Windows ou **"Accepted password"** no Linux) ocorre fora desta janela, a ferramenta regista um alerta com o utilizador, o IP de origem, a hora e o motivo específico (ex.: *"Fora do Expediente (03:22)"* ou *"Fim de Semana (Sábado às 14:10)"*).

---

## 5. Eventos do Windows (Logs de Segurança)

No Windows, os eventos de auditoria são identificados por códigos numéricos chamados **Event IDs**:

### ID 4624 — Logon com Sucesso
- **O que significa**: Um utilizador ou serviço autenticou-se com sucesso no Windows ou Active Directory.
- **Importância no SOC**: Permite ter o controlo volumétrico de acessos normais. Se um pico de falhas for seguido de um 4624 do mesmo IP, a conta pode ter sido invadida com sucesso.

### ID 4625 — Logon com Falha
- **O que significa**: Uma tentativa de entrada no sistema foi recusada (palavra-passe errada ou utilizador inexistente).
- **Importância no SOC**: É o evento base para alimentar os motores de deteção de Força Bruta e Password Spraying.

### ID 4740 — Conta de Utilizador Bloqueada
- **O que significa**: Uma conta foi desativada temporariamente pelo sistema por exceder o número de tentativas erradas permitidas pela política de segurança (*Account Lockout Policy*).
- **Importância no SOC**: Demonstra o impacto do ataque. A ferramenta extrai quem foi bloqueado, a que horas e em que computador o bloqueio ocorreu.

### ID 4720 — Conta de Utilizador Criada (Indicador de Persistência)
- **O que significa**: Uma nova conta de utilizador local ou de domínio foi criada no sistema.
- **Importância no SOC**: Em incidentes de segurança, após comprometer um servidor, os atacantes frequentemente criam contas locais adicionais (backdoors) para garantir acesso contínuo mesmo que a senha original seja alterada.

### ID 4728 — Membro Adicionado a Grupo de Segurança (Elevação de Privilégios)
- **O que significa**: Um utilizador foi adicionado a um grupo de segurança global com privilégios elevados (ex.: *Domain Admins*, *Administrators*, *Enterprise Admins*).
- **Importância no SOC**: É um dos alertas de maior criticidade num SOC. Se uma conta recém-criada for adicionada a um grupo administrativo, trata-se de um indicador quase certo de elevação de privilégios (*Privilege Escalation*).

### ID 4672 — Privilégios Especiais Atribuídos (Superadministrador)
- **O que significa**: Um utilizador iniciou sessão com direitos administrativos especiais (como `SeDebugPrivilege`, `SeBackupPrivilege` ou `SeTakeOwnershipPrivilege`).
- **Importância no SOC**: Permite auditar exatamente quando e onde foram exercidos direitos de superutilizador, distinguindo logons comuns de ações com potencial destrutivo ou de bypass de controlos de segurança.

---

## 6. Mensagens do Linux (`auth.log` / `secure`)

No Linux, o serviço OpenSSH (`sshd`) regista os acessos em texto:

### "Failed password for..."
- **O que significa**: Tentativa falhada de login SSH (palavra-passe errada ou utilizador inexistente no sistema).
- **Importância no SOC**: Equivalente direto do evento 4625 do Windows. Permite correlacionar IPs atacantes e utilizadores visados.

### "Accepted password for..."
- **O que significa**: Sessão SSH autorizada com sucesso por autenticação de palavra-passe.
- **Importância no SOC**: Equivalente ao evento 4624 do Windows. Garante a visibilidade dos acessos autorizados ao servidor.

---

## 7. Deteção Automática do Formato

A ferramenta lê as primeiras linhas do ficheiro e adapta-se automaticamente:
1. **Ficheiro Vazio**: se o ficheiro estiver sem dados, emite um aviso seguro e amigável sem provocar erros no programa.
2. **Formato Linux**: identifica linhas típicas do serviço OpenSSH (`sshd`, `failed password`, `accepted password`).
3. **Formato Windows CSV**: identifica cabeçalhos ou campos típicos do Visualizador de Eventos (`ID do evento`, `4625`, `4624`, `4740`).
