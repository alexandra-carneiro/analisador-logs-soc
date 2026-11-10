"""
analisador-logs-soc
Ferramenta simples para análise de logs de segurança (Windows e Linux auth.log).
Desenvolvida para o dia a dia de analistas de SOC (Security Operations Center).
Funciona apenas com a biblioteca padrão do Python 3.
"""

import sys
import os
import csv
import re
from datetime import datetime, timedelta
from collections import Counter

# Assegura que o terminal no Windows consiga imprimir acentos e caracteres UTF-8
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass


# ==============================================================================
# CONSTANTES DE CONFIGURAÇÃO (Podes alterar estes valores conforme a tua regra)
# ==============================================================================
# Mínimo de falhas de login do mesmo IP para ser considerado força bruta
LIMITE_FALHAS_BRUTE_FORCE = 5

# Janela de tempo (em minutos) para agrupar as falhas de login de um mesmo IP
JANELA_MINUTOS_BRUTE_FORCE = 10

# Nome do ficheiro onde o relatório final será guardado
FICHEIRO_RELATORIO_SAIDA = "relatorio.txt"


# ==============================================================================
# FUNÇÕES DE LEITURA E IDENTIFICAÇÃO DE FICHEIROS
# ==============================================================================

def ler_linhas_ficheiro(caminho_ficheiro):
    """
    Lê um ficheiro de texto linha a linha de forma segura.
    Testa codificações comuns (utf-8, utf-8 com BOM, latin-1, cp1252) para evitar erros
    quando o Windows exporta ficheiros com caracteres acentuados.
    """
    if not os.path.exists(caminho_ficheiro):
        return None, f"Erro: O ficheiro '{caminho_ficheiro}' não foi encontrado."

    codificacoes = ["utf-8-sig", "utf-8", "latin-1", "cp1252"]
    
    for codificacao in codificacoes:
        try:
            with open(caminho_ficheiro, mode="r", encoding=codificacao) as f:
                linhas = f.readlines()
                return linhas, None
        except (UnicodeDecodeError, PermissionError):
            continue

    return None, f"Erro: Não foi possível ler o ficheiro '{caminho_ficheiro}' com codificações de texto comuns."


def detetar_formato(linhas):
    """
    Deteta o formato dos logs com base no conteúdo das linhas.
    Retorna 'WINDOWS' para CSV do Visualizador de Eventos,
    'LINUX' para ficheiro auth.log do sshd,
    ou None se o formato não for reconhecido.
    """
    if not linhas:
        return None

    # Olhamos para as primeiras 30 linhas com conteúdo para identificar o padrão
    amostra = [linha.strip() for linha in linhas if linha.strip()][:30]
    if not amostra:
        return None

    texto_amostra = "\n".join(amostra).lower()

    # Padrão Linux sshd: termos clássicos como 'sshd', 'failed password' ou 'accepted password'
    if "sshd" in texto_amostra or "failed password" in texto_amostra or "accepted password" in texto_amostra:
        return "LINUX"

    # Padrão Windows CSV: termos habituais em cabeçalhos de eventos de segurança
    termos_windows = ["id do evento", "event id", "eventid", "4625", "4624", "4740", "palavras-chave", "keywords"]
    for termo in termos_windows:
        if termo in texto_amostra:
            return "WINDOWS"

    # Se a primeira linha contiver separadores de CSV (vírgula ou ponto e vírgula)
    primeira_linha = amostra[0]
    if "," in primeira_linha or ";" in primeira_linha:
        return "WINDOWS"

    return None


# ==============================================================================
# FUNÇÕES DE PROCESSAMENTO: WINDOWS (CSV)
# ==============================================================================

def normalizar_nome_coluna(nome):
    """
    Remove espaços e converte para minúsculas para facilitar a procura
    por nomes de colunas que podem variar ligeiramente entre versões do Windows.
    """
    if not nome:
        return ""
    return nome.strip().lower()


def converter_data_windows(texto_data):
    """
    Tenta converter uma string de data/hora do Windows para um objeto datetime.
    Se não conseguir ou se o campo estiver vazio, retorna None sem crashar.
    """
    if not texto_data:
        return None

    texto_data = texto_data.strip()
    formatos = [
        "%d/%m/%Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
        "%m/%d/%Y %H:%M:%S",
        "%d/%m/%Y %H:%M",
        "%Y-%m-%d %H:%M",
        "%m/%d/%Y %I:%M:%S %p",
        "%d/%m/%Y %I:%M:%S %p",
        "%Y-%m-%dT%H:%M:%S",
    ]

    for formato in formatos:
        try:
            return datetime.strptime(texto_data, formato)
        except ValueError:
            continue

    return None


def analisar_logs_windows(linhas):
    """
    Processa os eventos do Windows a partir das linhas CSV.
    Retorna um dicionário estruturado com as métricas recolhidas.
    """
    # Deteta se o delimitador é vírgula ou ponto e vírgula (comum no Windows em português)
    primeira_linha = next((linha for linha in linhas if linha.strip()), "")
    delimitador = ";" if primeira_linha.count(";") > primeira_linha.count(",") else ","

    leitor = csv.reader(linhas, delimiter=delimitador)
    
    # Procura a linha de cabeçalho
    cabecalho = None
    for linha in leitor:
        if linha and any(campo.strip() for campo in linha):
            cabecalho = [normalizar_nome_coluna(col) for col in linha]
            break

    if not cabecalho:
        return {
            "formato": "Windows (CSV)",
            "total_falhas": 0,
            "total_sucessos": 0,
            "total_bloqueios": 0,
            "falhas_por_utilizador": Counter(),
            "falhas_por_ip": Counter(),
            "falhas_timestamps_por_ip": {},
            "contas_bloqueadas": []
        }

    # Mapeia os índices das colunas mais importantes
    idx_evento = None
    idx_data = None
    idx_utilizador = None
    idx_ip = None
    idx_computador = None

    for i, col in enumerate(cabecalho):
        if any(chave in col for chave in ["id do evento", "event id", "eventid", "id"]):
            if idx_evento is None:
                idx_evento = i
        elif any(chave in col for chave in ["data e hora", "date and time", "timecreated", "timestamp", "data", "hora"]):
            if idx_data is None:
                idx_data = i
        elif any(chave in col for chave in ["utilizador", "user", "targetusername", "account name", "nome da conta"]):
            if idx_utilizador is None:
                idx_utilizador = i
        elif any(chave in col for chave in ["ip de origem", "source ip", "ipaddress", "endereço de rede", "ip"]):
            if idx_ip is None:
                idx_ip = i
        elif any(chave in col for chave in ["computador", "computer", "computername"]):
            if idx_computador is None:
                idx_computador = i

    # Estruturas para guardar os dados
    falhas_por_utilizador = Counter()
    falhas_por_ip = Counter()
    falhas_timestamps_por_ip = {}
    contas_bloqueadas = []
    total_sucessos = 0
    total_falhas = 0

    # Percorre cada registo do CSV
    for linha in leitor:
        if not linha or not any(campo.strip() for campo in linha):
            continue

        # Obtém o valor de cada coluna com tolerância a colunas ausentes ou vazias
        id_evento = linha[idx_evento].strip() if idx_evento is not None and idx_evento < len(linha) else ""
        data_texto = linha[idx_data].strip() if idx_data is not None and idx_data < len(linha) else ""
        utilizador = linha[idx_utilizador].strip() if idx_utilizador is not None and idx_utilizador < len(linha) else ""
        ip_origem = linha[idx_ip].strip() if idx_ip is not None and idx_ip < len(linha) else ""
        computador = linha[idx_computador].strip() if idx_computador is not None and idx_computador < len(linha) else ""

        # Limpeza de valores vazios ou de preenchimento padrão do Windows ("-")
        utilizador = utilizador if utilizador and utilizador != "-" else "Desconhecido"
        ip_origem = ip_origem if ip_origem and ip_origem != "-" else "Desconhecido / Local"
        data_dt = converter_data_windows(data_texto)

        # Evento 4624: Logon com sucesso
        if id_evento == "4624":
            total_sucessos += 1

        # Evento 4625: Logon com falha
        elif id_evento == "4625":
            total_falhas += 1
            falhas_por_utilizador[utilizador] += 1
            falhas_por_ip[ip_origem] += 1

            if ip_origem not in falhas_timestamps_por_ip:
                falhas_timestamps_por_ip[ip_origem] = []
            
            falhas_timestamps_por_ip[ip_origem].append({
                "tempo": data_dt,
                "utilizador": utilizador
            })

        # Evento 4740: Conta bloqueada
        elif id_evento == "4740":
            contas_bloqueadas.append({
                "utilizador": utilizador,
                "hora": data_texto if data_texto else "Hora desconhecida",
                "computador": computador if computador else "-"
            })

    return {
        "formato": "Windows (CSV)",
        "total_falhas": total_falhas,
        "total_sucessos": total_sucessos,
        "total_bloqueios": len(contas_bloqueadas),
        "falhas_por_utilizador": falhas_por_utilizador,
        "falhas_por_ip": falhas_por_ip,
        "falhas_timestamps_por_ip": falhas_timestamps_por_ip,
        "contas_bloqueadas": contas_bloqueadas
    }


# ==============================================================================
# FUNÇÕES DE PROCESSAMENTO: LINUX (auth.log)
# ==============================================================================

def converter_data_linux(texto_data):
    """
    Tenta converter a data de uma linha do auth.log.
    Exemplos: 'Nov 10 09:12:01' ou formato ISO '2026-11-10T09:12:01'.
    Se não incluir o ano, adiciona explicitamente o ano atual para evitar ambiguidades.
    """
    if not texto_data:
        return None

    texto_data = texto_data.strip()
    ano_atual = datetime.now().year

    # Formato tradicional syslog: 'Nov 10 09:12:01' ou 'Nov  2 09:12:01'
    # Adicionamos o ano atual à frente da string para evitar o DeprecationWarning do Python 3.12+
    partes = texto_data.split()
    if len(partes) == 3:
        mes, dia, hora = partes
        texto_com_ano = f"{ano_atual} {mes} {dia.zfill(2)} {hora}"
        try:
            return datetime.strptime(texto_com_ano, "%Y %b %d %H:%M:%S")
        except ValueError:
            pass

    # Formatos alternativos com ano ou ISO
    formatos = [
        "%Y-%m-%dT%H:%M:%S",
        "%b %d %Y %H:%M:%S",
        "%Y-%m-%d %H:%M:%S"
    ]
    for formato in formatos:
        try:
            return datetime.strptime(texto_data[:19], formato)
        except ValueError:
            continue

    return None


def analisar_logs_linux(linhas):
    """
    Processa as linhas de texto do auth.log (serviço sshd).
    Retorna um dicionário estruturado com as métricas recolhidas.
    """
    falhas_por_utilizador = Counter()
    falhas_por_ip = Counter()
    falhas_timestamps_por_ip = {}
    total_sucessos = 0
    total_falhas = 0

    # Regex para capturar data/hora tradicional (ex: 'Nov 10 14:02:10') ou ISO no início da linha
    regex_data_syslog = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")
    regex_data_iso = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")

    # Regex para linhas de falha de login do sshd
    # Cobre: 'Failed password for invalid user admin from 192.168.1.10' e 'Failed password for root from 192.168.1.10'
    regex_falha = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")

    # Regex para linhas de sucesso do sshd: 'Accepted password for joao from 192.168.1.5'
    regex_sucesso = re.compile(r"Accepted password for \S+ from \S+")

    for linha in linhas:
        linha_limpa = linha.strip()
        if not linha_limpa:
            continue

        # Extrai a data/hora do início da linha se disponível
        data_dt = None
        match_data = regex_data_syslog.match(linha_limpa) or regex_data_iso.match(linha_limpa)
        if match_data:
            data_dt = converter_data_linux(match_data.group(1))

        # Verifica se é uma linha de sucesso
        if regex_sucesso.search(linha_limpa):
            total_sucessos += 1

        # Verifica se é uma linha de falha
        match_falha = regex_falha.search(linha_limpa)
        if match_falha:
            total_falhas += 1
            utilizador = match_falha.group(1).strip()
            ip_origem = match_falha.group(2).strip()

            falhas_por_utilizador[utilizador] += 1
            falhas_por_ip[ip_origem] += 1

            if ip_origem not in falhas_timestamps_por_ip:
                falhas_timestamps_por_ip[ip_origem] = []

            falhas_timestamps_por_ip[ip_origem].append({
                "tempo": data_dt,
                "utilizador": utilizador
            })

    return {
        "formato": "Linux (auth.log / sshd)",
        "total_falhas": total_falhas,
        "total_sucessos": total_sucessos,
        "total_bloqueios": 0,  # O auth.log básico foca nas falhas e acessos SSH
        "falhas_por_utilizador": falhas_por_utilizador,
        "falhas_por_ip": falhas_por_ip,
        "falhas_timestamps_por_ip": falhas_timestamps_por_ip,
        "contas_bloqueadas": []
    }


# ==============================================================================
# DETEÇÃO DE FORÇA BRUTA (BRUTE FORCE)
# ==============================================================================

def calcular_gravidade_brute_force(num_falhas):
    """
    Atribui um nível de gravidade simples com base no volume de tentativas:
    - Baixo: 5 a 9 falhas na janela de tempo
    - Médio: 10 a 19 falhas na janela de tempo
    - Alto: 20 ou mais falhas na janela de tempo
    """
    if num_falhas >= 20:
        return "Alto"
    elif num_falhas >= 10:
        return "Médio"
    else:
        return "Baixo"


def detetar_padroes_brute_force(falhas_timestamps_por_ip):
    """
    Analisa os registos de falha por IP para identificar padrões de força bruta:
    5 ou mais falhas de login do mesmo IP dentro de uma janela de 10 minutos.
    Retorna uma lista de alertas ordenados por gravidade.
    """
    alertas = []
    janela_delta = timedelta(minutes=JANELA_MINUTOS_BRUTE_FORCE)

    for ip, registos in falhas_timestamps_por_ip.items():
        if len(registos) < LIMITE_FALHAS_BRUTE_FORCE:
            continue

        # Separa os registos que têm timestamp válido
        registos_com_tempo = [r for r in registos if r["tempo"] is not None]
        
        # Ordena cronologicamente
        registos_com_tempo.sort(key=lambda x: x["tempo"])

        pico_falhas_janela = 0
        janela_inicio = None
        janela_fim = None

        # Janela deslizante para encontrar o intervalo mais intenso de falhas
        if registos_com_tempo:
            for i in range(len(registos_com_tempo)):
                t_inicio = registos_com_tempo[i]["tempo"]
                t_limite = t_inicio + janela_delta
                
                # Conta quantas falhas ocorreram dentro dos 10 minutos a partir de t_inicio
                falhas_na_janela = [r for r in registos_com_tempo[i:] if r["tempo"] <= t_limite]
                qtd = len(falhas_na_janela)

                if qtd > pico_falhas_janela:
                    pico_falhas_janela = qtd
                    janela_inicio = t_inicio
                    janela_fim = falhas_na_janela[-1]["tempo"]
        else:
            # Caso não haja timestamps válidos mas o total ultrapasse o limite
            pico_falhas_janela = len(registos)

        # Se atingiu o limite de força bruta
        if pico_falhas_janela >= LIMITE_FALHAS_BRUTE_FORCE:
            gravidade = calcular_gravidade_brute_force(pico_falhas_janela)
            utilizadores_visados = list(dict.fromkeys(r["utilizador"] for r in registos))
            
            alertas.append({
                "ip": ip,
                "gravidade": gravidade,
                "falhas_janela": pico_falhas_janela,
                "total_falhas_ip": len(registos),
                "inicio": janela_inicio.strftime("%d/%m/%Y %H:%M:%S") if janela_inicio else "N/D",
                "fim": janela_fim.strftime("%d/%m/%Y %H:%M:%S") if janela_fim else "N/D",
                "utilizadores": utilizadores_visados
            })

    # Ordena alertas: Alto primeiro, depois Médio, depois Baixo
    ordem_gravidade = {"Alto": 0, "Médio": 1, "Baixo": 2}
    alertas.sort(key=lambda a: (ordem_gravidade.get(a["gravidade"], 3), -a["falhas_janela"]))

    return alertas


# ==============================================================================
# GERAÇÃO DO RELATÓRIO
# ==============================================================================

def gerar_texto_relatorio(dados, alertas_brute_force):
    """
    Constrói o texto final do relatório em português claro e objetivo,
    pronto para impressão no terminal e gravação em ficheiro.
    """
    linhas = []
    separador = "=" * 65
    sub_separador = "-" * 65

    linhas.append(separador)
    linhas.append("           RELATÓRIO DE ANÁLISE DE LOGS - SOC")
    linhas.append(separador)
    linhas.append(f"Formato detetado: {dados['formato']}")
    linhas.append(f"Regra de Força Bruta: {LIMITE_FALHAS_BRUTE_FORCE}+ falhas em {JANELA_MINUTOS_BRUTE_FORCE} minutos")
    linhas.append("")

    # 1. TOTAIS GERAIS
    linhas.append("1. RESUMO GERAL")
    linhas.append(sub_separador)
    linhas.append(f"  - Total de logins com falha:   {dados['total_falhas']}")
    linhas.append(f"  - Total de logins com sucesso: {dados['total_sucessos']}")
    linhas.append(f"  - Contas bloqueadas:           {dados['total_bloqueios']}")
    linhas.append("")

    # 2. TOP 5 UTILIZADORES COM MAIS FALHAS
    linhas.append("2. TOP 5 UTILIZADORES COM MAIS FALHAS")
    linhas.append(sub_separador)
    top_utilizadores = dados["falhas_por_utilizador"].most_common(5)
    if top_utilizadores:
        for pos, (utilizador, contagem) in enumerate(top_utilizadores, start=1):
            linhas.append(f"  {pos}. Utilizador: {utilizador:<25} | Falhas: {contagem}")
    else:
        linhas.append("  Nenhuma falha de utilizador registada.")
    linhas.append("")

    # 3. TOP 5 IPs COM MAIS FALHAS
    linhas.append("3. TOP 5 IPs DE ORIGEM COM MAIS FALHAS")
    linhas.append(sub_separador)
    top_ips = dados["falhas_por_ip"].most_common(5)
    if top_ips:
        for pos, (ip, contagem) in enumerate(top_ips, start=1):
            linhas.append(f"  {pos}. IP: {ip:<33} | Falhas: {contagem}")
    else:
        linhas.append("  Nenhum IP com falhas registado.")
    linhas.append("")

    # 4. PADRÕES DE FORÇA BRUTA DETETADOS
    linhas.append("4. PADRÕES DE FORÇA BRUTA DETETADOS")
    linhas.append(sub_separador)
    if alertas_brute_force:
        for alerta in alertas_brute_force:
            linhas.append(f"  [ALERTA - Gravidade: {alerta['gravidade'].upper()}]")
            linhas.append(f"    - IP de Origem:        {alerta['ip']}")
            linhas.append(f"    - Falhas na Janela:    {alerta['falhas_janela']} tentativas em <= {JANELA_MINUTOS_BRUTE_FORCE} minutos")
            linhas.append(f"    - Total de Falhas IP:  {alerta['total_falhas_ip']}")
            if alerta['inicio'] != "N/D":
                linhas.append(f"    - Período do Ataque:   {alerta['inicio']} até {alerta['fim']}")
            alvos = ", ".join(alerta['utilizadores'][:5])
            if len(alerta['utilizadores']) > 5:
                alvos += f" e mais {len(alerta['utilizadores']) - 5} contas"
            linhas.append(f"    - Contas Visadas:      {alvos}")
            linhas.append("")
    else:
        linhas.append("  Nenhum padrão suspeito de força bruta foi identificado.")
        linhas.append("")

    # 5. CONTAS BLOQUEADAS (Relevante no Windows ID 4740)
    if dados["contas_bloqueadas"]:
        linhas.append("5. DETALHE DE CONTAS BLOQUEADAS (EVENTO 4740)")
        linhas.append(sub_separador)
        for b in dados["contas_bloqueadas"]:
            linhas.append(f"  - Conta: {b['utilizador']:<20} | Hora: {b['hora']:<20} | Computador: {b['computador']}")
        linhas.append("")

    linhas.append(separador)
    linhas.append("Fim do relatório.")
    linhas.append(separador)

    return "\n".join(linhas)


def salvar_relatorio(texto_relatorio, caminho_saida=FICHEIRO_RELATORIO_SAIDA):
    """
    Grava o relatório num ficheiro de texto (relatorio.txt).
    """
    try:
        with open(caminho_saida, mode="w", encoding="utf-8") as f:
            f.write(texto_relatorio)
        return True, None
    except Exception as e:
        return False, str(e)


# ==============================================================================
# FUNÇÃO PRINCIPAL (MAIN)
# ==============================================================================

def main():
    """
    Ponto de entrada da ferramenta.
    Pode receber o caminho do ficheiro por argumento na linha de comandos:
        python analisador.py caminho/do/ficheiro.log
    Ou solicita interativamente caso nenhum argumento seja passado.
    """
    # Determina o ficheiro a analisar
    if len(sys.argv) > 1:
        caminho_ficheiro = sys.argv[1]
    else:
        print("--- Analisador de Logs para SOC ---")
        try:
            caminho_ficheiro = input("Introduza o caminho do ficheiro de logs: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\nOperação cancelada.")
            return

    if not caminho_ficheiro:
        print("Erro: Nenhum caminho de ficheiro foi indicado.")
        return

    # Lê o ficheiro
    linhas, erro = ler_linhas_ficheiro(caminho_ficheiro)
    if erro:
        print(erro)
        return

    # Verifica se o ficheiro está vazio
    linhas_com_conteudo = [l for l in linhas if l.strip()]
    if not linhas_com_conteudo:
        mensagem_vazio = f"Aviso: O ficheiro '{caminho_ficheiro}' está vazio. Não há dados para analisar."
        print("\n" + mensagem_vazio)
        salvar_relatorio(mensagem_vazio + "\n")
        return

    # Deteta o formato (Windows CSV ou Linux auth.log)
    formato = detetar_formato(linhas)
    if formato == "WINDOWS":
        dados = analisar_logs_windows(linhas)
    elif formato == "LINUX":
        dados = analisar_logs_linux(linhas)
    else:
        print("\nErro: Formato de log não reconhecido.")
        print("A ferramenta aceita CSV do Visualizador de Eventos do Windows ou ficheiro auth.log do Linux.")
        return

    # Se não houver dados úteis extraídos
    if dados["total_falhas"] == 0 and dados["total_sucessos"] == 0 and dados["total_bloqueios"] == 0:
        mensagem_sem_dados = f"Aviso: O ficheiro '{caminho_ficheiro}' não contém eventos relevantes de login ou segurança."
        print("\n" + mensagem_sem_dados)
        salvar_relatorio(mensagem_sem_dados + "\n")
        return

    # Deteta padrões de força bruta
    alertas_brute_force = detetar_padroes_brute_force(dados["falhas_timestamps_por_ip"])

    # Gera o relatório formatado
    relatorio_texto = gerar_texto_relatorio(dados, alertas_brute_force)

    # Imprime no terminal
    print("\n" + relatorio_texto)

    # Guarda no ficheiro relatorio.txt
    sucesso, erro_salvar = salvar_relatorio(relatorio_texto)
    if sucesso:
        print(f"\n[+] Relatório guardado com sucesso no ficheiro '{FICHEIRO_RELATORIO_SAIDA}'.\n")
    else:
        print(f"\n[-] Erro ao guardar o ficheiro de relatório: {erro_salvar}\n")


if __name__ == "__main__":
    main()
