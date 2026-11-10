"""
analisador-logs-soc
Ferramenta simples para análise de logs de segurança (Windows e Linux auth.log).
Desenvolvida para o dia a dia de analistas de SOC (Security Operations Center).
Gera relatórios no terminal, em texto (.txt) e em PDF (.pdf com cores por gravidade).
Suporta deteção de Força Bruta (ataque vertical) e Password Spraying (ataque horizontal).
"""

import sys
import os
import csv
import json
import re
import ipaddress
from datetime import datetime, timedelta
from collections import Counter

# Assegura que o terminal no Windows consiga imprimir acentos e caracteres UTF-8
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

# Tentativa de importação da biblioteca opcional fpdf2 para gerar PDF
try:
    from fpdf import FPDF, XPos, YPos
    FPDF_DISPONIVEL = True
except ImportError:
    FPDF_DISPONIVEL = False

# Tentativa de importação da biblioteca requests para consultar a AbuseIPDB
try:
    import requests
    REQUESTS_DISPONIVEL = True
except ImportError:
    REQUESTS_DISPONIVEL = False


# ==============================================================================
# CONFIGURAÇÃO DE THREAT INTELLIGENCE (AbuseIPDB)
# ==============================================================================
# Carrega a chave de API da AbuseIPDB a partir do ambiente ou ficheiro local .env
ABUSEIPDB_API_KEY = os.environ.get("ABUSEIPDB_API_KEY")

def carregar_chaves_env_local():
    """
    Carrega chaves de API a partir de um ficheiro .env local caso existam,
    sem necessitar de bibliotecas de terceiros como python-dotenv.
    """
    global ABUSEIPDB_API_KEY
    caminho_env = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(caminho_env):
        try:
            with open(caminho_env, mode="r", encoding="utf-8") as f:
                for linha in f:
                    linha = linha.strip()
                    if linha and not linha.startswith("#") and "=" in linha:
                        chave, valor = linha.split("=", 1)
                        chave = chave.strip()
                        valor = valor.strip().strip('"').strip("'")
                        if chave == "ABUSEIPDB_API_KEY" and not ABUSEIPDB_API_KEY:
                            ABUSEIPDB_API_KEY = valor
        except Exception:
            pass

carregar_chaves_env_local()


# ==============================================================================
# CONSTANTES DE CONFIGURAÇÃO (Podes alterar estes valores conforme a tua regra)
# ==============================================================================
# Regras de Força Bruta Tradicional (Brute Force Concentrado / Vertical)
LIMITE_FALHAS_BRUTE_FORCE = 5       # Mínimo de falhas para suspeita de força bruta
JANELA_MINUTOS_BRUTE_FORCE = 10     # Intervalo de tempo (em minutos) para a janela

# Regras de Password Spraying (Ataque Horizontal / Muitas contas com poucas tentativas)
LIMITE_CONTAS_PASSWORD_SPRAYING = 4        # Mínimo de contas distintas visadas pelo mesmo IP
MAX_TENTATIVAS_POR_CONTA_SPRAYING = 3      # Média máxima de tentativas por conta (evita bloqueio)
JANELA_MINUTOS_PASSWORD_SPRAYING = 30      # Janela temporal para agrupar o ataque de spray

# Regras de Logons Fora de Horas (Horário Normal de Expediente)
HORARIO_INICIO_EXPEDIENTE = 8                     # Início do expediente (08:00)
HORARIO_FIM_EXPEDIENTE = 19                       # Fim do expediente (19:00)
CONSIDERAR_FIM_DE_SEMANA_FORA_DE_HORAS = True     # Sábados e domingos são considerados fora de horas

# Ficheiros onde os relatórios serão guardados
FICHEIRO_RELATORIO_TXT = "relatorio.txt"
FICHEIRO_RELATORIO_PDF = "relatorio.pdf"
FICHEIRO_RELATORIO_JSON = "relatorio.json"


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

    amostra = [linha.strip() for linha in linhas if linha.strip()][:30]
    if not amostra:
        return None

    texto_amostra = "\n".join(amostra).lower()

    if "sshd" in texto_amostra or "failed password" in texto_amostra or "accepted password" in texto_amostra:
        return "LINUX"

    termos_windows = ["id do evento", "event id", "eventid", "4625", "4624", "4740", "palavras-chave", "keywords"]
    for termo in termos_windows:
        if termo in texto_amostra:
            return "WINDOWS"

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


def verificar_fora_de_horas(data_dt):
    """
    Verifica se um evento com timestamp ocorreu fora do horário de expediente:
    - Antes de HORARIO_INICIO_EXPEDIENTE ou a partir de HORARIO_FIM_EXPEDIENTE
    - Ou em fins de semana se CONSIDERAR_FIM_DE_SEMANA_FORA_DE_HORAS for True.
    Retorna (True, motivo) ou (False, None).
    """
    if not data_dt:
        return False, None

    dia_semana = data_dt.weekday()  # 0 = Segunda-feira ... 5 = Sábado, 6 = Domingo
    hora = data_dt.hour

    if CONSIDERAR_FIM_DE_SEMANA_FORA_DE_HORAS and dia_semana in (5, 6):
        dia_nome = "Sábado" if dia_semana == 5 else "Domingo"
        return True, f"Fim de Semana ({dia_nome} às {data_dt.strftime('%H:%M')})"

    if hora < HORARIO_INICIO_EXPEDIENTE or hora >= HORARIO_FIM_EXPEDIENTE:
        return True, f"Fora do Expediente ({data_dt.strftime('%H:%M')})"

    return False, None


def analisar_logs_windows(linhas):
    """
    Processa os eventos do Windows a partir das linhas CSV.
    Retorna um dicionário estruturado com as métricas recolhidas.
    """
    primeira_linha = next((linha for linha in linhas if linha.strip()), "")
    delimitador = ";" if primeira_linha.count(";") > primeira_linha.count(",") else ","

    leitor = csv.reader(linhas, delimiter=delimitador)
    
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

    falhas_por_utilizador = Counter()
    falhas_por_ip = Counter()
    falhas_timestamps_por_ip = {}
    contas_bloqueadas = []
    contas_criadas = []
    membros_adicionados_grupo = []
    logons_privilegios_especiais = []
    logons_fora_de_horas = []
    total_sucessos = 0
    total_falhas = 0

    for linha in leitor:
        if not linha or not any(campo.strip() for campo in linha):
            continue

        id_evento = linha[idx_evento].strip() if idx_evento is not None and idx_evento < len(linha) else ""
        data_texto = linha[idx_data].strip() if idx_data is not None and idx_data < len(linha) else ""
        utilizador = linha[idx_utilizador].strip() if idx_utilizador is not None and idx_utilizador < len(linha) else ""
        ip_origem = linha[idx_ip].strip() if idx_ip is not None and idx_ip < len(linha) else ""
        computador = linha[idx_computador].strip() if idx_computador is not None and idx_computador < len(linha) else ""

        utilizador = utilizador if utilizador and utilizador != "-" else "Desconhecido"
        ip_origem = ip_origem if ip_origem and ip_origem != "-" else "Desconhecido / Local"
        data_dt = converter_data_windows(data_texto)

        # Evento 4624: Logon com sucesso
        if id_evento == "4624":
            total_sucessos += 1
            e_fora, motivo = verificar_fora_de_horas(data_dt)
            if e_fora:
                logons_fora_de_horas.append({
                    "utilizador": utilizador,
                    "ip": ip_origem,
                    "hora": data_texto if data_texto else "Hora desconhecida",
                    "computador": computador if computador else "-",
                    "motivo": motivo
                })

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

        # Evento 4720: Conta de utilizador criada (Indicador de Persistência)
        elif id_evento == "4720":
            contas_criadas.append({
                "utilizador": utilizador,
                "hora": data_texto if data_texto else "Hora desconhecida",
                "computador": computador if computador else "-"
            })

        # Evento 4728: Membro adicionado a grupo de segurança global (Elevação de Privilégios)
        elif id_evento == "4728":
            membros_adicionados_grupo.append({
                "utilizador": utilizador,
                "hora": data_texto if data_texto else "Hora desconhecida",
                "computador": computador if computador else "-"
            })

        # Evento 4672: Privilégios especiais atribuídos a novo logon (Superprivilégios de Administrador)
        elif id_evento == "4672":
            logons_privilegios_especiais.append({
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
        "contas_bloqueadas": contas_bloqueadas,
        "contas_criadas": contas_criadas,
        "membros_adicionados_grupo": membros_adicionados_grupo,
        "logons_privilegios_especiais": logons_privilegios_especiais,
        "logons_fora_de_horas": logons_fora_de_horas
    }


# ==============================================================================
# FUNÇÕES DE PROCESSAMENTO: LINUX (auth.log)
# ==============================================================================

def converter_data_linux(texto_data):
    """
    Tenta converter a data de uma linha do auth.log.
    Exemplos: 'Nov 10 09:12:01' ou formato ISO '2026-11-10T09:12:01'.
    Se não incluir o ano, adiciona explicitamente o ano atual para evitar avisos.
    """
    if not texto_data:
        return None

    texto_data = texto_data.strip()
    ano_atual = datetime.now().year

    partes = texto_data.split()
    if len(partes) == 3:
        mes, dia, hora = partes
        texto_com_ano = f"{ano_atual} {mes} {dia.zfill(2)} {hora}"
        try:
            return datetime.strptime(texto_com_ano, "%Y %b %d %H:%M:%S")
        except ValueError:
            pass

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
    logons_fora_de_horas = []
    total_sucessos = 0
    total_falhas = 0

    regex_data_syslog = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")
    regex_data_iso = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
    regex_falha = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
    regex_sucesso = re.compile(r"Accepted password for (\S+) from (\S+)")

    for linha in linhas:
        linha_limpa = linha.strip()
        if not linha_limpa:
            continue

        data_dt = None
        match_data = regex_data_syslog.match(linha_limpa) or regex_data_iso.match(linha_limpa)
        if match_data:
            data_dt = converter_data_linux(match_data.group(1))

        match_sucesso = regex_sucesso.search(linha_limpa)
        if match_sucesso:
            total_sucessos += 1
            u_sucesso = match_sucesso.group(1).strip()
            ip_sucesso = match_sucesso.group(2).strip()
            e_fora, motivo = verificar_fora_de_horas(data_dt)
            if e_fora:
                logons_fora_de_horas.append({
                    "utilizador": u_sucesso,
                    "ip": ip_sucesso,
                    "hora": data_dt.strftime("%d/%m/%Y %H:%M:%S") if data_dt else "Hora desconhecida",
                    "computador": "Servidor Linux (SSH)",
                    "motivo": motivo
                })

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
        "total_bloqueios": 0,
        "falhas_por_utilizador": falhas_por_utilizador,
        "falhas_por_ip": falhas_por_ip,
        "falhas_timestamps_por_ip": falhas_timestamps_por_ip,
        "contas_bloqueadas": [],
        "contas_criadas": [],
        "membros_adicionados_grupo": [],
        "logons_privilegios_especiais": [],
        "logons_fora_de_horas": logons_fora_de_horas
    }


# ==============================================================================
# DETEÇÃO DE FORÇA BRUTA (BRUTE FORCE - ATAQUE VERTICAL)
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


def detetar_padroes_brute_force(falhas_timestamps_por_ip, ips_excluidos_spray=None):
    """
    Analisa os registos de falha por IP para identificar padrões de força bruta:
    5 ou mais falhas de login do mesmo IP dentro de uma janela de 10 minutos.
    Retorna uma lista de alertas ordenados por gravidade.
    """
    if ips_excluidos_spray is None:
        ips_excluidos_spray = set()

    alertas = []
    janela_delta = timedelta(minutes=JANELA_MINUTOS_BRUTE_FORCE)

    for ip, registos in falhas_timestamps_por_ip.items():
        # Se o IP já tiver sido classificado primariamente como Password Spraying,
        # evitamos duplicar o alerta para manter o relatório limpo
        if ip in ips_excluidos_spray:
            continue

        if len(registos) < LIMITE_FALHAS_BRUTE_FORCE:
            continue

        registos_com_tempo = [r for r in registos if r["tempo"] is not None]
        registos_com_tempo.sort(key=lambda x: x["tempo"])

        pico_falhas_janela = 0
        janela_inicio = None
        janela_fim = None

        if registos_com_tempo:
            for i in range(len(registos_com_tempo)):
                t_inicio = registos_com_tempo[i]["tempo"]
                t_limite = t_inicio + janela_delta
                
                falhas_na_janela = [r for r in registos_com_tempo[i:] if r["tempo"] <= t_limite]
                qtd = len(falhas_na_janela)

                if qtd > pico_falhas_janela:
                    pico_falhas_janela = qtd
                    janela_inicio = t_inicio
                    janela_fim = falhas_na_janela[-1]["tempo"]
        else:
            pico_falhas_janela = len(registos)

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

    ordem_gravidade = {"Alto": 0, "Médio": 1, "Baixo": 2}
    alertas.sort(key=lambda a: (ordem_gravidade.get(a["gravidade"], 3), -a["falhas_janela"]))

    return alertas


# ==============================================================================
# DETEÇÃO DE PASSWORD SPRAYING (ATAQUE HORIZONTAL)
# ==============================================================================

def calcular_gravidade_spray(num_contas):
    """
    Classifica a gravidade do ataque de password spraying pelo número de contas visadas:
    - Baixo: 4 a 6 contas distintas
    - Médio: 7 a 14 contas distintas
    - Alto: 15 ou mais contas distintas
    """
    if num_contas >= 15:
        return "Alto"
    elif num_contas >= 7:
        return "Médio"
    else:
        return "Baixo"


def detetar_padroes_password_spraying(falhas_timestamps_por_ip):
    """
    Identifica tentativas de password spraying:
    Um único IP a tentar autenticar-se em múltiplas contas diferentes
    com poucas tentativas em cada conta (comportamento típico para evitar bloqueios).
    Retorna uma lista de alertas ordenados por gravidade.
    """
    alertas_spray = []
    janela_delta = timedelta(minutes=JANELA_MINUTOS_PASSWORD_SPRAYING)

    for ip, registos in falhas_timestamps_por_ip.items():
        if len(registos) < LIMITE_CONTAS_PASSWORD_SPRAYING:
            continue

        registos_com_tempo = [r for r in registos if r["tempo"] is not None]
        registos_com_tempo.sort(key=lambda x: x["tempo"])

        pico_contas_janela = 0
        janela_inicio = None
        janela_fim = None
        contas_janela_melhor = []
        qtd_falhas_janela = 0

        if registos_com_tempo:
            for i in range(len(registos_com_tempo)):
                t_inicio = registos_com_tempo[i]["tempo"]
                t_limite = t_inicio + janela_delta

                falhas_na_janela = [r for r in registos_com_tempo[i:] if r["tempo"] <= t_limite]
                contas_unicas = list(dict.fromkeys(r["utilizador"] for r in falhas_na_janela))

                if len(contas_unicas) > pico_contas_janela:
                    pico_contas_janela = len(contas_unicas)
                    contas_janela_melhor = contas_unicas
                    qtd_falhas_janela = len(falhas_na_janela)
                    janela_inicio = t_inicio
                    janela_fim = falhas_na_janela[-1]["tempo"]
        else:
            contas_unicas = list(dict.fromkeys(r["utilizador"] for r in registos))
            pico_contas_janela = len(contas_unicas)
            contas_janela_melhor = contas_unicas
            qtd_falhas_janela = len(registos)

        # Regra de Password Spraying:
        # Pelo menos LIMITE_CONTAS_PASSWORD_SPRAYING contas distintas e baixa média de tentativas por conta
        if pico_contas_janela >= LIMITE_CONTAS_PASSWORD_SPRAYING:
            media_tentativas = qtd_falhas_janela / pico_contas_janela
            if media_tentativas <= MAX_TENTATIVAS_POR_CONTA_SPRAYING:
                gravidade = calcular_gravidade_spray(pico_contas_janela)
                alertas_spray.append({
                    "ip": ip,
                    "gravidade": gravidade,
                    "contas_visadas": contas_janela_melhor,
                    "total_contas": pico_contas_janela,
                    "total_tentativas": qtd_falhas_janela,
                    "media_por_conta": round(media_tentativas, 1),
                    "inicio": janela_inicio.strftime("%d/%m/%Y %H:%M:%S") if janela_inicio else "N/D",
                    "fim": janela_fim.strftime("%d/%m/%Y %H:%M:%S") if janela_fim else "N/D"
                })

    ordem_gravidade = {"Alto": 0, "Médio": 1, "Baixo": 2}
    alertas_spray.sort(key=lambda a: (ordem_gravidade.get(a["gravidade"], 3), -a["total_contas"]))

    return alertas_spray


# ==============================================================================
# ENRIQUECIMENTO DE THREAT INTELLIGENCE (AbuseIPDB)
# ==============================================================================

def eh_ip_publico(ip_str):
    """
    Verifica se a string é um endereço IP público válido.
    Retorna False para IPs privados (RFC 1918), loopback ou texto.
    """
    if not ip_str or any(termo in ip_str.lower() for termo in ["desconhecido", "local", "none", "-"]):
        return False
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        return not (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_reserved or ip_obj.is_link_local)
    except ValueError:
        return False


def consultar_reputacao_abuseipdb(ip, api_key):
    """
    Consulta um IP público na API v2 da AbuseIPDB.
    Retorna um dicionário com métricas de reputação ou informações de erro.
    """
    if not REQUESTS_DISPONIVEL or not api_key:
        return None

    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }

    try:
        resposta = requests.get(url, headers=headers, params=params, timeout=5)
        if resposta.status_code == 200:
            info = resposta.json().get("data", {})
            return {
                "ip": ip,
                "score": info.get("abuseConfidenceScore", 0),
                "pais": info.get("countryCode", "N/D"),
                "isp": info.get("isp", "N/D"),
                "total_denuncias": info.get("totalReports", 0),
                "tipo_uso": info.get("usageType", "N/D")
            }
        elif resposta.status_code == 401:
            return {"ip": ip, "erro": "Chave de API AbuseIPDB inválida"}
        else:
            return {"ip": ip, "erro": f"HTTP {resposta.status_code}"}
    except Exception as e:
        return {"ip": ip, "erro": f"Erro de conexão ({type(e).__name__})"}


def enriquecer_ips_com_abuseipdb(ips_para_analisar, api_key=ABUSEIPDB_API_KEY):
    """
    Percorre a lista de IPs suspeitos e enriquece os IPs públicos usando a AbuseIPDB.
    """
    if not api_key:
        return {}

    resultados = {}
    ips_publicos = list(dict.fromkeys(ip for ip in ips_para_analisar if eh_ip_publico(ip)))

    # Limita a 10 consultas por execução para respeitar os limites de quota gratuita
    for ip in ips_publicos[:10]:
        res = consultar_reputacao_abuseipdb(ip, api_key)
        if res:
            resultados[ip] = res

    return resultados


# ==============================================================================
# GERAÇÃO DO RELATÓRIO: TEXTO E CONSOLA
# ==============================================================================

def gerar_texto_relatorio(dados, alertas_brute_force, alertas_spray, dados_abuseipdb=None):
    """
    Constrói o texto final do relatório em português claro e objetivo,
    pronto para impressão no terminal e gravação em ficheiro .txt.
    """
    linhas = []
    separador = "=" * 65
    sub_separador = "-" * 65

    linhas.append(separador)
    linhas.append("           RELATÓRIO DE ANÁLISE DE LOGS - SOC")
    linhas.append(separador)
    linhas.append(f"Formato detetado: {dados['formato']}")
    linhas.append(f"Regras de Deteção: Brute Force ({LIMITE_FALHAS_BRUTE_FORCE}+ falhas/{JANELA_MINUTOS_BRUTE_FORCE}m) | Password Spraying ({LIMITE_CONTAS_PASSWORD_SPRAYING}+ contas/{JANELA_MINUTOS_PASSWORD_SPRAYING}m)")
    linhas.append("")

    # 1. TOTAIS GERAIS
    linhas.append("1. RESUMO GERAL")
    linhas.append(sub_separador)
    linhas.append(f"  - Total de logins com falha:   {dados['total_falhas']}")
    linhas.append(f"  - Total de logins com sucesso: {dados['total_sucessos']}")
    linhas.append(f"  - Contas bloqueadas (4740):    {dados['total_bloqueios']}")
    if dados.get("logons_fora_de_horas"):
        linhas.append(f"  - Logons fora de horas:        {len(dados['logons_fora_de_horas'])}")
    if dados.get("contas_criadas"):
        linhas.append(f"  - Contas criadas (4720):       {len(dados['contas_criadas'])}")
    if dados.get("membros_adicionados_grupo"):
        linhas.append(f"  - Adições a grupos priv. (4728):{len(dados['membros_adicionados_grupo'])}")
    if dados.get("logons_privilegios_especiais"):
        linhas.append(f"  - Logons privilegiados (4672):  {len(dados['logons_privilegios_especiais'])}")
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

    # 4. PADRÕES DE FORÇA BRUTA (ATAQUE VERTICAL / CONCENTRADO)
    linhas.append("4. PADRÕES DE FORÇA BRUTA (ATAQUE VERTICAL / CONCENTRADO)")
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
        linhas.append("  Nenhum padrão suspeito de força bruta concentrada foi identificado.")
        linhas.append("")

    # 5. PADRÕES DE PASSWORD SPRAYING (ATAQUE HORIZONTAL / DISPERSÃO)
    linhas.append("5. PADRÕES DE PASSWORD SPRAYING (DISPERSÃO DE CONTAS)")
    linhas.append(sub_separador)
    if alertas_spray:
        for spray in alertas_spray:
            linhas.append(f"  [ALERTA - Gravidade: {spray['gravidade'].upper()}]")
            linhas.append(f"    - IP de Origem:        {spray['ip']}")
            linhas.append(f"    - Contas Distintas:    {spray['total_contas']} contas visadas")
            linhas.append(f"    - Média por Conta:     {spray['media_por_conta']} tentativas (spray horizontal)")
            linhas.append(f"    - Total de Tentativas: {spray['total_tentativas']}")
            if spray['inicio'] != "N/D":
                linhas.append(f"    - Período do Ataque:   {spray['inicio']} até {spray['fim']}")
            alvos = ", ".join(spray['contas_visadas'][:6])
            if len(spray['contas_visadas']) > 6:
                alvos += f" e mais {len(spray['contas_visadas']) - 6} contas"
            linhas.append(f"    - Contas Visadas:      {alvos}")
            linhas.append("")
    else:
        linhas.append("  Nenhum padrão suspeito de password spraying foi identificado.")
        linhas.append("")

    # 6. CONTAS BLOQUEADAS (Relevante no Windows ID 4740)
    if dados["contas_bloqueadas"]:
        linhas.append("6. DETALHE DE CONTAS BLOQUEADAS (EVENTO 4740)")
        linhas.append(sub_separador)
        for b in dados["contas_bloqueadas"]:
            linhas.append(f"  - Conta: {b['utilizador']:<20} | Hora: {b['hora']:<20} | Computador: {b['computador']}")
        linhas.append("")

    # 7. EVENTOS DE AUDITORIA CRÍTICOS (WINDOWS: 4720, 4728, 4672)
    tem_eventos_auditoria = (
        dados.get("contas_criadas") or
        dados.get("membros_adicionados_grupo") or
        dados.get("logons_privilegios_especiais")
    )
    if tem_eventos_auditoria:
        linhas.append("7. PERSISTÊNCIA E PRIVILÉGIOS (EVENTOS 4720, 4728, 4672)")
        linhas.append(sub_separador)
        if dados.get("contas_criadas"):
            linhas.append("  [!] CONTAS DE UTILIZADOR CRIADAS (ID 4720 - Indicador de Persistência):")
            for c in dados["contas_criadas"]:
                linhas.append(f"    - Conta Criada: {c['utilizador']:<20} | Hora: {c['hora']:<20} | Computador: {c['computador']}")
            linhas.append("")
        if dados.get("membros_adicionados_grupo"):
            linhas.append("  [!] ADIÇÕES A GRUPOS PRIVILEGIADOS (ID 4728 - Elevação de Privilégios):")
            for m in dados["membros_adicionados_grupo"]:
                linhas.append(f"    - Membro:       {m['utilizador']:<20} | Hora: {m['hora']:<20} | Computador: {m['computador']}")
            linhas.append("")
        if dados.get("logons_privilegios_especiais"):
            linhas.append("  [!] LOGONS COM SUPERPRIVILÉGIOS (ID 4672 - Administrador Especial):")
            for p in dados["logons_privilegios_especiais"]:
                linhas.append(f"    - Conta:        {p['utilizador']:<20} | Hora: {p['hora']:<20} | Computador: {p['computador']}")
            linhas.append("")

    # 8. LOGONS FORA DE HORAS (SUSPEITOS)
    if dados.get("logons_fora_de_horas"):
        linhas.append("8. LOGONS BEM-SUCEDIDOS FORA DE HORAS (SUSPEITOS)")
        linhas.append(sub_separador)
        for h in dados["logons_fora_de_horas"]:
            linhas.append(f"  - Conta: {h['utilizador']:<20} | IP: {h['ip']:<18} | Hora: {h['hora']} | Motivo: {h['motivo']}")
        linhas.append("")

    # 9. ENRIQUECIMENTO DE THREAT INTELLIGENCE (ABUSEIPDB)
    linhas.append("9. THREAT INTELLIGENCE (ABUSEIPDB)")
    linhas.append(sub_separador)
    if dados_abuseipdb:
        for ip, info in dados_abuseipdb.items():
            if "erro" in info:
                linhas.append(f"  - IP: {ip:<18} | Erro na consulta: {info['erro']}")
            else:
                score = info["score"]
                classificacao = "MUITO ALTO" if score >= 80 else ("ALTO" if score >= 50 else ("MÉDIO" if score >= 20 else "BAIXO"))
                linhas.append(f"  - IP: {ip:<18} | Score de Abuso: {score}% ({classificacao})")
                linhas.append(f"    • País: {info['pais']} | ISP: {info['isp']} | Uso: {info['tipo_uso']}")
                linhas.append(f"    • Denúncias na Comunidade: {info['total_denuncias']} denúncias públicas")
                linhas.append("")
    else:
        if not ABUSEIPDB_API_KEY:
            linhas.append("  [i] Enriquecimento externo desativado. Para ativar, defina a chave gratuita")
            linhas.append("      na variável de ambiente ABUSEIPDB_API_KEY ou num ficheiro .env local.")
        else:
            linhas.append("  Nenhum IP público relevante identificado para consulta na AbuseIPDB.")
        linhas.append("")

    linhas.append(separador)
    linhas.append("Fim do relatório.")
    linhas.append(separador)

    return "\n".join(linhas)


def salvar_relatorio_txt(texto_relatorio, caminho_saida=FICHEIRO_RELATORIO_TXT):
    """
    Grava o relatório num ficheiro de texto (.txt).
    """
    try:
        with open(caminho_saida, mode="w", encoding="utf-8") as f:
            f.write(texto_relatorio)
        return True, None
    except Exception as e:
        return False, str(e)


def salvar_relatorio_json(dados, alertas_brute_force, alertas_spray, dados_abuseipdb=None, caminho_saida=FICHEIRO_RELATORIO_JSON):
    """
    Grava os dados da análise num ficheiro JSON estruturado,
    ideal para ingestão automatizada por SIEMs (Splunk, Elastic, Sentinel) ou SOARs.
    """
    try:
        estrutura = {
            "@timestamp": datetime.now().isoformat() + "Z",
            "ferramenta": "analisador-logs-soc",
            "formato_origem": dados["formato"],
            "metricas_gerais": {
                "total_falhas": dados["total_falhas"],
                "total_sucessos": dados["total_sucessos"],
                "total_bloqueios": dados["total_bloqueios"],
                "total_logons_fora_de_horas": len(dados.get("logons_fora_de_horas", [])),
                "total_contas_criadas": len(dados.get("contas_criadas", [])),
                "total_adicoes_grupo_privilegiado": len(dados.get("membros_adicionados_grupo", [])),
                "total_logons_superprivilegiados": len(dados.get("logons_privilegios_especiais", []))
            },
            "top_utilizadores_falhas": [
                {"utilizador": u, "falhas": count} for u, count in dados["falhas_por_utilizador"].most_common(10)
            ],
            "top_ips_falhas": [
                {"ip": ip, "falhas": count} for ip, count in dados["falhas_por_ip"].most_common(10)
            ],
            "alertas_forca_bruta": alertas_brute_force,
            "alertas_password_spraying": alertas_spray,
            "threat_intelligence_abuseipdb": dados_abuseipdb if dados_abuseipdb else {},
            "logons_fora_de_horas": dados.get("logons_fora_de_horas", []),
            "contas_bloqueadas": dados.get("contas_bloqueadas", []),
            "eventos_privilegios_windows": {
                "contas_criadas": dados.get("contas_criadas", []),
                "membros_adicionados_grupo": dados.get("membros_adicionados_grupo", []),
                "logons_privilegios_especiais": dados.get("logons_privilegios_especiais", [])
            }
        }

        with open(caminho_saida, mode="w", encoding="utf-8") as f:
            json.dump(estrutura, f, indent=2, ensure_ascii=False)
        return True, None
    except Exception as e:
        return False, str(e)


# ==============================================================================
# GERAÇÃO DO RELATÓRIO EM PDF (COM FPDF2 E CORES DE GRAVIDADE)
# ==============================================================================

if FPDF_DISPONIVEL:
    class RelatorioSOCPDF(FPDF):
        def header(self):
            # Barra superior azul escura (estilo SOC / Cybersecurity)
            self.set_fill_color(15, 23, 42)  # Slate 900
            self.rect(0, 0, 210, 26, "F")
            
            # Título principal
            self.set_text_color(255, 255, 255)
            self.set_font("helvetica", "B", 14)
            self.set_xy(10, 5)
            self.cell(0, 8, "RELATORIO DE ANALISE DE SEGURANCA - SOC", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            # Subtítulo
            self.set_font("helvetica", "", 9)
            self.set_text_color(203, 213, 225)  # Slate 300
            self.cell(0, 5, "Triagem Operacional: Forca Bruta, Password Spraying e Bloqueios", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            self.ln(6)

        def footer(self):
            self.set_y(-15)
            self.set_font("helvetica", "I", 8)
            self.set_text_color(148, 163, 184)  # Slate 400
            self.cell(0, 10, f"Pagina {self.page_no()} | analisador-logs-soc - Documento Confidencial de Uso Interno", align="C")


def gerar_relatorio_pdf(dados, alertas_brute_force, alertas_spray, dados_abuseipdb=None, caminho_saida=FICHEIRO_RELATORIO_PDF):
    """
    Gera um relatório profissional em PDF usando fpdf2.
    Inclui cabeçalho executivo, tabelas limpas e alertas com cores de gravidade.
    """
    if not FPDF_DISPONIVEL:
        return False, "A biblioteca 'fpdf2' não está instalada. Execute: pip install fpdf2"

    try:
        pdf = RelatorioSOCPDF()
        pdf.set_auto_page_break(auto=True, margin=18)
        pdf.add_page()

        # Metadados do Relatório
        pdf.set_font("helvetica", "", 9)
        pdf.set_text_color(71, 85, 105)
        agora_str = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
        pdf.cell(100, 5, f"Data da Analise: {agora_str}")
        pdf.cell(0, 5, f"Formato dos Logs: {dados['formato']}", align="R", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.cell(0, 5, f"Deteccao: Brute Force ({LIMITE_FALHAS_BRUTE_FORCE}+ falhas/{JANELA_MINUTOS_BRUTE_FORCE}m) | Spray ({LIMITE_CONTAS_PASSWORD_SPRAYING}+ contas/{JANELA_MINUTOS_PASSWORD_SPRAYING}m)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

        # 1. RESUMO GERAL (3 Caixas de Métricas)
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 7, "1. Resumo Executivo das Metricas", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        largura_caixa = 60
        altura_caixa = 16
        x_inicial = 10
        y_inicial = pdf.get_y()

        # Caixa 1: Falhas
        pdf.set_xy(x_inicial, y_inicial)
        pdf.set_fill_color(254, 242, 242)
        pdf.set_draw_color(239, 68, 68)
        pdf.rect(x_inicial, y_inicial, largura_caixa, altura_caixa, "DF")
        pdf.set_xy(x_inicial + 2, y_inicial + 2)
        pdf.set_font("helvetica", "B", 8)
        pdf.set_text_color(185, 28, 28)
        pdf.cell(largura_caixa - 4, 4, "LOGINS COM FALHA", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_xy(x_inicial + 2, y_inicial + 7)
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(largura_caixa - 4, 7, str(dados["total_falhas"]), align="C")

        # Caixa 2: Sucessos
        x_caixa2 = x_inicial + largura_caixa + 5
        pdf.set_xy(x_caixa2, y_inicial)
        pdf.set_fill_color(240, 253, 244)
        pdf.set_draw_color(34, 197, 94)
        pdf.rect(x_caixa2, y_inicial, largura_caixa, altura_caixa, "DF")
        pdf.set_xy(x_caixa2 + 2, y_inicial + 2)
        pdf.set_font("helvetica", "B", 8)
        pdf.set_text_color(21, 128, 61)
        pdf.cell(largura_caixa - 4, 4, "LOGINS COM SUCESSO", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_xy(x_caixa2 + 2, y_inicial + 7)
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(largura_caixa - 4, 7, str(dados["total_sucessos"]), align="C")

        # Caixa 3: Bloqueios
        x_caixa3 = x_caixa2 + largura_caixa + 5
        pdf.set_xy(x_caixa3, y_inicial)
        pdf.set_fill_color(254, 243, 199)
        pdf.set_draw_color(245, 158, 11)
        pdf.rect(x_caixa3, y_inicial, largura_caixa, altura_caixa, "DF")
        pdf.set_xy(x_caixa3 + 2, y_inicial + 2)
        pdf.set_font("helvetica", "B", 8)
        pdf.set_text_color(180, 83, 9)
        pdf.cell(largura_caixa - 4, 4, "CONTAS BLOQUEADAS", align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.set_xy(x_caixa3 + 2, y_inicial + 7)
        pdf.set_font("helvetica", "B", 14)
        pdf.cell(largura_caixa - 4, 7, str(dados["total_bloqueios"]), align="C")

        pdf.set_xy(10, y_inicial + altura_caixa + 6)

        # 2. TABELAS: TOP UTILIZADORES E TOP IPS
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 6, "2. Top Alvos e Origens Mais Recorrentes", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        y_tab = pdf.get_y()

        pdf.set_xy(10, y_tab)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_draw_color(203, 213, 225)
        pdf.set_font("helvetica", "B", 8)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(65, 6, "Top 5 Utilizadores Visados", border=1, fill=True)
        pdf.cell(27, 6, "Falhas", border=1, align="C", fill=True)

        pdf.set_xy(107, y_tab)
        pdf.cell(66, 6, "Top 5 IPs de Origem", border=1, fill=True)
        pdf.cell(27, 6, "Falhas", border=1, align="C", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        top_u = dados["falhas_por_utilizador"].most_common(5)
        top_i = dados["falhas_por_ip"].most_common(5)
        max_linhas = max(len(top_u), len(top_i), 1)

        pdf.set_font("helvetica", "", 8)
        for i in range(max_linhas):
            y_linha = pdf.get_y()
            pdf.set_xy(10, y_linha)
            if i < len(top_u):
                u_nome, u_qtd = top_u[i]
                pdf.cell(65, 5, f"{i+1}. {u_nome[:30]}", border=1)
                pdf.cell(27, 5, str(u_qtd), border=1, align="C")
            else:
                pdf.cell(65, 5, "-", border=1)
                pdf.cell(27, 5, "-", border=1, align="C")

            pdf.set_xy(107, y_linha)
            if i < len(top_i):
                ip_nome, ip_qtd = top_i[i]
                pdf.cell(66, 5, f"{i+1}. {ip_nome[:30]}", border=1)
                pdf.cell(27, 5, str(ip_qtd), border=1, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            else:
                pdf.cell(66, 5, "-", border=1)
                pdf.cell(27, 5, "-", border=1, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.ln(5)

        # 3. PADRÕES DE FORÇA BRUTA (ATAQUE VERTICAL)
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 6, "3. Forca Bruta Concentrada (Ataques Verticais)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if not alertas_brute_force:
            pdf.set_font("helvetica", "I", 8)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 5, "Nenhum padrao de forca bruta concentrada identificado.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(2)
        else:
            for alerta in alertas_brute_force:
                gravidade = alerta["gravidade"].upper()
                if gravidade == "ALTO":
                    cor_fundo = (254, 226, 226)
                    cor_borda = (220, 38, 38)
                    cor_texto = (153, 27, 27)
                elif gravidade in ["MÉDIO", "MEDIO"]:
                    cor_fundo = (254, 243, 199)
                    cor_borda = (217, 119, 6)
                    cor_texto = (146, 64, 14)
                else:
                    cor_fundo = (224, 242, 254)
                    cor_borda = (2, 132, 199)
                    cor_texto = (7, 89, 133)

                x_alerta = 10
                y_alerta = pdf.get_y()
                altura_alerta = 22

                if y_alerta + altura_alerta > 270:
                    pdf.add_page()
                    y_alerta = pdf.get_y()

                pdf.set_fill_color(*cor_fundo)
                pdf.set_draw_color(*cor_borda)
                pdf.rect(x_alerta, y_alerta, 190, altura_alerta, "DF")

                pdf.set_xy(x_alerta + 3, y_alerta + 2)
                pdf.set_font("helvetica", "B", 9)
                pdf.set_text_color(*cor_texto)
                pdf.cell(0, 4, f"[ALERTA BRUTE FORCE - GRAVIDADE {gravidade}] IP de Origem: {alerta['ip']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.set_font("helvetica", "", 8)
                pdf.set_text_color(51, 65, 85)
                pdf.set_xy(x_alerta + 5, y_alerta + 7)
                pdf.cell(90, 4, f"- Falhas na Janela: {alerta['falhas_janela']} tentativas em <= {JANELA_MINUTOS_BRUTE_FORCE}m")
                pdf.cell(0, 4, f"- Total de Falhas: {alerta['total_falhas_ip']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.set_xy(x_alerta + 5, y_alerta + 11)
                pdf.cell(0, 4, f"- Periodo: {alerta['inicio']} ate {alerta['fim']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.set_xy(x_alerta + 5, y_alerta + 15)
                alvos_str = ", ".join(alerta["utilizadores"][:6])
                if len(alerta["utilizadores"]) > 6:
                    alvos_str += f" e mais {len(alerta['utilizadores']) - 6} contas"
                pdf.cell(0, 4, f"- Contas Visadas: {alvos_str}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.set_xy(10, y_alerta + altura_alerta + 3)

        pdf.ln(3)

        # 4. PADRÕES DE PASSWORD SPRAYING (ATAQUE HORIZONTAL)
        if pdf.get_y() > 240:
            pdf.add_page()

        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 6, "4. Password Spraying Detetado (Ataques Horizontais)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if not alertas_spray:
            pdf.set_font("helvetica", "I", 8)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 5, "Nenhum padrao de password spraying identificado.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(2)
        else:
            for spray in alertas_spray:
                gravidade = spray["gravidade"].upper()
                if gravidade == "ALTO":
                    cor_fundo = (254, 226, 226)
                    cor_borda = (220, 38, 38)
                    cor_texto = (153, 27, 27)
                elif gravidade in ["MÉDIO", "MEDIO"]:
                    cor_fundo = (254, 243, 199)
                    cor_borda = (217, 119, 6)
                    cor_texto = (146, 64, 14)
                else:
                    cor_fundo = (243, 232, 255)  # Roxo suave para spray
                    cor_borda = (147, 51, 234)
                    cor_texto = (107, 33, 168)

                x_spray = 10
                y_spray = pdf.get_y()
                altura_spray = 23

                if y_spray + altura_spray > 270:
                    pdf.add_page()
                    y_spray = pdf.get_y()

                pdf.set_fill_color(*cor_fundo)
                pdf.set_draw_color(*cor_borda)
                pdf.rect(x_spray, y_spray, 190, altura_spray, "DF")

                pdf.set_xy(x_spray + 3, y_spray + 2)
                pdf.set_font("helvetica", "B", 9)
                pdf.set_text_color(*cor_texto)
                pdf.cell(0, 4, f"[ALERTA PASSWORD SPRAY - GRAVIDADE {gravidade}] IP de Origem: {spray['ip']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.set_font("helvetica", "", 8)
                pdf.set_text_color(51, 65, 85)
                pdf.set_xy(x_spray + 5, y_spray + 7)
                pdf.cell(90, 4, f"- Contas Distintas: {spray['total_contas']} utilizadores")
                pdf.cell(0, 4, f"- Media por Conta: {spray['media_por_conta']} tentativas (Spray Horizontal)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.set_xy(x_spray + 5, y_spray + 11)
                pdf.cell(0, 4, f"- Periodo: {spray['inicio']} ate {spray['fim']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.set_xy(x_spray + 5, y_spray + 15)
                contas_str = ", ".join(spray["contas_visadas"][:6])
                if len(spray["contas_visadas"]) > 6:
                    contas_str += f" e mais {len(spray['contas_visadas']) - 6} contas"
                pdf.cell(0, 4, f"- Utilizadores Alvo: {contas_str}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.set_xy(10, y_spray + altura_spray + 3)

        pdf.ln(3)

        # 5. CONTAS BLOQUEADAS (EVENTO 4740)
        if dados["contas_bloqueadas"]:
            if pdf.get_y() > 240:
                pdf.add_page()

            pdf.set_font("helvetica", "B", 11)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 6, "5. Detalhe de Contas Bloqueadas no Sistema (Evento 4740)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.set_fill_color(241, 245, 249)
            pdf.set_draw_color(203, 213, 225)
            pdf.set_font("helvetica", "B", 8)
            pdf.set_text_color(51, 65, 85)
            pdf.cell(60, 6, "Conta Bloqueada", border=1, fill=True)
            pdf.cell(65, 6, "Data e Hora do Bloqueio", border=1, fill=True)
            pdf.cell(65, 6, "Computador / Origem", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.set_font("helvetica", "", 8)
            for b in dados["contas_bloqueadas"]:
                pdf.cell(60, 5, b["utilizador"][:30], border=1)
                pdf.cell(65, 5, b["hora"][:30], border=1)
                pdf.cell(65, 5, b["computador"][:30], border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # 6. PERSISTÊNCIA E ELEVAÇÃO DE PRIVILÉGIOS (EVENTOS 4720, 4728, 4672)
        tem_eventos_auditoria = (
            dados.get("contas_criadas") or
            dados.get("membros_adicionados_grupo") or
            dados.get("logons_privilegios_especiais")
        )
        if tem_eventos_auditoria:
            if pdf.get_y() > 230:
                pdf.add_page()
            else:
                pdf.ln(3)

            pdf.set_font("helvetica", "B", 11)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 6, "6. Persistencia e Elevacao de Privilegios (Windows 4720, 4728, 4672)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.set_fill_color(254, 242, 242)
            pdf.set_draw_color(239, 68, 68)
            pdf.set_font("helvetica", "B", 8)
            pdf.set_text_color(185, 28, 28)
            pdf.cell(35, 6, "Tipo de Evento", border=1, fill=True)
            pdf.cell(50, 6, "Conta / Alvo", border=1, fill=True)
            pdf.cell(55, 6, "Data e Hora", border=1, fill=True)
            pdf.cell(50, 6, "Computador", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.set_font("helvetica", "", 8)
            pdf.set_text_color(51, 65, 85)

            for c in dados.get("contas_criadas", []):
                pdf.cell(35, 5, "4720 (Conta Criada)", border=1)
                pdf.cell(50, 5, c["utilizador"][:25], border=1)
                pdf.cell(55, 5, c["hora"][:25], border=1)
                pdf.cell(50, 5, c["computador"][:25], border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            for m in dados.get("membros_adicionados_grupo", []):
                pdf.cell(35, 5, "4728 (Membro Grupo)", border=1)
                pdf.cell(50, 5, m["utilizador"][:25], border=1)
                pdf.cell(55, 5, m["hora"][:25], border=1)
                pdf.cell(50, 5, m["computador"][:25], border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            for p in dados.get("logons_privilegios_especiais", []):
                pdf.cell(35, 5, "4672 (Superprivilegio)", border=1)
                pdf.cell(50, 5, p["utilizador"][:25], border=1)
                pdf.cell(55, 5, p["hora"][:25], border=1)
                pdf.cell(50, 5, p["computador"][:25], border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # 7. LOGONS FORA DE HORAS (SUSPEITOS)
        if dados.get("logons_fora_de_horas"):
            if pdf.get_y() > 230:
                pdf.add_page()
            else:
                pdf.ln(3)

            pdf.set_font("helvetica", "B", 11)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 6, "7. Logons Bem-sucedidos Fora de Horas (Suspeitos)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.set_fill_color(254, 243, 199)
            pdf.set_draw_color(245, 158, 11)
            pdf.set_font("helvetica", "B", 8)
            pdf.set_text_color(180, 83, 9)
            pdf.cell(45, 6, "Conta", border=1, fill=True)
            pdf.cell(45, 6, "IP de Origem", border=1, fill=True)
            pdf.cell(50, 6, "Data e Hora", border=1, fill=True)
            pdf.cell(50, 6, "Motivo do Alerta", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.set_font("helvetica", "", 8)
            pdf.set_text_color(51, 65, 85)
            for h in dados["logons_fora_de_horas"]:
                pdf.cell(45, 5, h["utilizador"][:25], border=1)
                pdf.cell(45, 5, h["ip"][:25], border=1)
                pdf.cell(50, 5, h["hora"][:25], border=1)
                pdf.cell(50, 5, h["motivo"][:25], border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # 8. THREAT INTELLIGENCE (ABUSEIPDB)
        if dados_abuseipdb:
            if pdf.get_y() > 230:
                pdf.add_page()
            else:
                pdf.ln(3)

            pdf.set_font("helvetica", "B", 11)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 6, "8. Enriquecimento de Threat Intelligence (AbuseIPDB)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.set_fill_color(241, 245, 249)
            pdf.set_draw_color(203, 213, 225)
            pdf.set_font("helvetica", "B", 8)
            pdf.set_text_color(51, 65, 85)
            pdf.cell(40, 6, "IP de Origem", border=1, fill=True)
            pdf.cell(30, 6, "Abuse Score", border=1, fill=True)
            pdf.cell(25, 6, "Pais", border=1, fill=True)
            pdf.cell(65, 6, "ISP / Organizacao", border=1, fill=True)
            pdf.cell(30, 6, "Denuncias", border=1, fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

            pdf.set_font("helvetica", "", 8)
            for ip_cons, info_cons in dados_abuseipdb.items():
                if "erro" not in info_cons:
                    score = info_cons["score"]
                    score_str = f"{score}% (Alto)" if score >= 50 else f"{score}%"
                    pdf.cell(40, 5, ip_cons[:20], border=1)
                    pdf.cell(30, 5, score_str, border=1)
                    pdf.cell(25, 5, info_cons.get("pais", "N/D")[:15], border=1)
                    pdf.cell(65, 5, info_cons.get("isp", "N/D")[:35], border=1)
                    pdf.cell(30, 5, str(info_cons.get("total_denuncias", 0)), border=1, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.output(caminho_saida)
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

    linhas, erro = ler_linhas_ficheiro(caminho_ficheiro)
    if erro:
        print(erro)
        return

    linhas_com_conteudo = [l for l in linhas if l.strip()]
    if not linhas_com_conteudo:
        mensagem_vazio = f"Aviso: O ficheiro '{caminho_ficheiro}' está vazio. Não há dados para analisar."
        print("\n" + mensagem_vazio)
        salvar_relatorio_txt(mensagem_vazio + "\n")
        return

    formato = detetar_formato(linhas)
    if formato == "WINDOWS":
        dados = analisar_logs_windows(linhas)
    elif formato == "LINUX":
        dados = analisar_logs_linux(linhas)
    else:
        print("\nErro: Formato de log não reconhecido.")
        print("A ferramenta aceita CSV do Visualizador de Eventos do Windows ou ficheiro auth.log do Linux.")
        return

    if dados["total_falhas"] == 0 and dados["total_sucessos"] == 0 and dados["total_bloqueios"] == 0:
        mensagem_sem_dados = f"Aviso: O ficheiro '{caminho_ficheiro}' não contém eventos relevantes de login ou segurança."
        print("\n" + mensagem_sem_dados)
        salvar_relatorio_txt(mensagem_sem_dados + "\n")
        return

    # 1. Deteta padrões de Password Spraying (Ataque horizontal)
    alertas_spray = detetar_padroes_password_spraying(dados["falhas_timestamps_por_ip"])
    ips_em_spray = {s["ip"] for s in alertas_spray}

    # 2. Deteta padrões de Força Bruta (Ataque vertical concentrado)
    alertas_brute_force = detetar_padroes_brute_force(dados["falhas_timestamps_por_ip"], ips_excluidos_spray=ips_em_spray)

    # 3. Enriquecimento opcional com Threat Intelligence (AbuseIPDB)
    ips_suspeitos = list(dict.fromkeys(
        [a["ip"] for a in alertas_brute_force] +
        [s["ip"] for s in alertas_spray] +
        [ip for ip, _ in dados["falhas_por_ip"].most_common(5)]
    ))
    dados_abuseipdb = enriquecer_ips_com_abuseipdb(ips_suspeitos)

    # Gera o relatório em texto para terminal e ficheiro .txt
    relatorio_texto = gerar_texto_relatorio(dados, alertas_brute_force, alertas_spray, dados_abuseipdb)
    print("\n" + relatorio_texto)

    # 1. Guarda em .txt
    sucesso_txt, erro_txt = salvar_relatorio_txt(relatorio_texto)
    if sucesso_txt:
        print(f"[+] Relatório em texto guardado em '{FICHEIRO_RELATORIO_TXT}'.")
    else:
        print(f"[-] Erro ao guardar ficheiro .txt: {erro_txt}")

    # 2. Guarda em JSON (estruturado para SIEMs e outras ferramentas)
    sucesso_json, erro_json = salvar_relatorio_json(dados, alertas_brute_force, alertas_spray, dados_abuseipdb)
    if sucesso_json:
        print(f"[+] Relatório estruturado em JSON guardado em '{FICHEIRO_RELATORIO_JSON}'.")
    else:
        print(f"[-] Erro ao guardar ficheiro JSON: {erro_json}")

    # 3. Guarda em PDF (se fpdf2 estiver disponível)
    if FPDF_DISPONIVEL:
        sucesso_pdf, erro_pdf = gerar_relatorio_pdf(dados, alertas_brute_force, alertas_spray, dados_abuseipdb, FICHEIRO_RELATORIO_PDF)
        if sucesso_pdf:
            print(f"[+] Relatório executivo em PDF guardado com sucesso em '{FICHEIRO_RELATORIO_PDF}'.\n")
        else:
            print(f"[-] Erro ao gerar ficheiro PDF: {erro_pdf}\n")
    else:
        print("[i] Dica: Instale 'fpdf2' (pip install fpdf2) para gerar automaticamente o relatório em PDF com alertas coloridos.\n")


if __name__ == "__main__":
    main()
