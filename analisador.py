"""
analisador-logs-soc
Ferramenta simples para análise de logs de segurança (Windows e Linux auth.log).
Desenvolvida para o dia a dia de analistas de SOC (Security Operations Center).
Gera relatórios no terminal, em texto (.txt) e em PDF (.pdf com cores por gravidade).
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

# Tentativa de importação da biblioteca opcional fpdf2 para gerar PDF
try:
    from fpdf import FPDF, XPos, YPos
    FPDF_DISPONIVEL = True
except ImportError:
    FPDF_DISPONIVEL = False


# ==============================================================================
# CONSTANTES DE CONFIGURAÇÃO (Podes alterar estes valores conforme a tua regra)
# ==============================================================================
# Mínimo de falhas de login do mesmo IP para ser considerado força bruta
LIMITE_FALHAS_BRUTE_FORCE = 5

# Janela de tempo (em minutos) para agrupar as falhas de login de um mesmo IP
JANELA_MINUTOS_BRUTE_FORCE = 10

# Ficheiros onde os relatórios serão guardados
FICHEIRO_RELATORIO_TXT = "relatorio.txt"
FICHEIRO_RELATORIO_PDF = "relatorio.pdf"


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
    total_sucessos = 0
    total_falhas = 0

    regex_data_syslog = re.compile(r"^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})")
    regex_data_iso = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")
    regex_falha = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)")
    regex_sucesso = re.compile(r"Accepted password for \S+ from \S+")

    for linha in linhas:
        linha_limpa = linha.strip()
        if not linha_limpa:
            continue

        data_dt = None
        match_data = regex_data_syslog.match(linha_limpa) or regex_data_iso.match(linha_limpa)
        if match_data:
            data_dt = converter_data_linux(match_data.group(1))

        if regex_sucesso.search(linha_limpa):
            total_sucessos += 1

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
# GERAÇÃO DO RELATÓRIO: TEXTO E CONSOLA
# ==============================================================================

def gerar_texto_relatorio(dados, alertas_brute_force):
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
            self.cell(0, 5, "Triagem Operacional de Eventos de Autenticacao e Deteccao de Ameacas", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            self.ln(6)

        def footer(self):
            # Posicionamento a 15 mm do fundo
            self.set_y(-15)
            self.set_font("helvetica", "I", 8)
            self.set_text_color(148, 163, 184)  # Slate 400
            self.cell(0, 10, f"Pagina {self.page_no()} | analisador-logs-soc - Documento Confidencial de Uso Interno", align="C")


def gerar_relatorio_pdf(dados, alertas_brute_force, caminho_saida=FICHEIRO_RELATORIO_PDF):
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
        pdf.cell(0, 5, f"Regra de Forca Bruta: {LIMITE_FALHAS_BRUTE_FORCE}+ falhas em {JANELA_MINUTOS_BRUTE_FORCE} minutos", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        pdf.ln(3)

        # 1. RESUMO GERAL (3 Caixas de Métricas)
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 7, "1. Resumo Executivo das Metricas", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        # Caixas: Falhas (Vermelho/Rosa), Sucessos (Verde), Bloqueios (Laranja)
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

        # 2. TABELAS LADO A LADO: TOP UTILIZADORES E TOP IPS
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 6, "2. Top Alvos e Origens Mais Recorrentes", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        col_w1 = 92
        col_w2 = 93
        y_tab = pdf.get_y()

        # Cabeçalho Tabela Utilizadores
        pdf.set_xy(10, y_tab)
        pdf.set_fill_color(241, 245, 249)
        pdf.set_draw_color(203, 213, 225)
        pdf.set_font("helvetica", "B", 8)
        pdf.set_text_color(51, 65, 85)
        pdf.cell(65, 6, "Top 5 Utilizadores Visados", border=1, fill=True)
        pdf.cell(27, 6, "Falhas", border=1, align="C", fill=True)

        # Cabeçalho Tabela IPs
        pdf.set_xy(107, y_tab)
        pdf.cell(66, 6, "Top 5 IPs de Origem", border=1, fill=True)
        pdf.cell(27, 6, "Falhas", border=1, align="C", fill=True, new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        # Linhas das Tabelas
        top_u = dados["falhas_por_utilizador"].most_common(5)
        top_i = dados["falhas_por_ip"].most_common(5)
        max_linhas = max(len(top_u), len(top_i), 1)

        pdf.set_font("helvetica", "", 8)
        for i in range(max_linhas):
            y_linha = pdf.get_y()
            # Coluna Utilizador
            pdf.set_xy(10, y_linha)
            if i < len(top_u):
                u_nome, u_qtd = top_u[i]
                pdf.cell(65, 5, f"{i+1}. {u_nome[:30]}", border=1)
                pdf.cell(27, 5, str(u_qtd), border=1, align="C")
            else:
                pdf.cell(65, 5, "-", border=1)
                pdf.cell(27, 5, "-", border=1, align="C")

            # Coluna IP
            pdf.set_xy(107, y_linha)
            if i < len(top_i):
                ip_nome, ip_qtd = top_i[i]
                pdf.cell(66, 5, f"{i+1}. {ip_nome[:30]}", border=1)
                pdf.cell(27, 5, str(ip_qtd), border=1, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            else:
                pdf.cell(66, 5, "-", border=1)
                pdf.cell(27, 5, "-", border=1, align="C", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        pdf.ln(5)

        # 3. PADRÕES DE FORÇA BRUTA COM CAIXAS COLORIDAS POR GRAVIDADE
        pdf.set_font("helvetica", "B", 11)
        pdf.set_text_color(15, 23, 42)
        pdf.cell(0, 6, "3. Padroes de Forca Bruta Detetados (Alertas)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        if not alertas_brute_force:
            pdf.set_font("helvetica", "I", 9)
            pdf.set_text_color(100, 116, 139)
            pdf.cell(0, 6, "Nenhum padrao suspeito de forca bruta foi identificado nos logs.", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            pdf.ln(3)
        else:
            for alerta in alertas_brute_force:
                gravidade = alerta["gravidade"].upper()

                # Definição das cores baseada na gravidade
                if gravidade == "ALTO":
                    # Fundo vermelho suave, borda vermelha, texto escuro
                    cor_fundo = (254, 226, 226)
                    cor_borda = (220, 38, 38)
                    cor_texto = (153, 27, 27)
                elif gravidade == "MÉDIO" or gravidade == "MEDIO":
                    # Fundo amarelo/laranja suave, borda laranja
                    cor_fundo = (254, 243, 199)
                    cor_borda = (217, 119, 6)
                    cor_texto = (146, 64, 14)
                else:
                    # BAIXO: Fundo azul suave, borda azul
                    cor_fundo = (224, 242, 254)
                    cor_borda = (2, 132, 199)
                    cor_texto = (7, 89, 133)

                # Caixa de Alerta
                x_alerta = 10
                y_alerta = pdf.get_y()
                altura_alerta = 25

                # Quebra de página suave caso não caiba
                if y_alerta + altura_alerta > 270:
                    pdf.add_page()
                    y_alerta = pdf.get_y()

                pdf.set_fill_color(*cor_fundo)
                pdf.set_draw_color(*cor_borda)
                pdf.rect(x_alerta, y_alerta, 190, altura_alerta, "DF")

                # Cabeçalho do alerta com badge
                pdf.set_xy(x_alerta + 3, y_alerta + 2)
                pdf.set_font("helvetica", "B", 9)
                pdf.set_text_color(*cor_texto)
                pdf.cell(0, 5, f"[ALERTA - GRAVIDADE {gravidade}] IP de Origem: {alerta['ip']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                # Detalhes do alerta
                pdf.set_font("helvetica", "", 8)
                pdf.set_text_color(51, 65, 85)
                pdf.set_xy(x_alerta + 5, y_alerta + 7)
                pdf.cell(90, 4, f"- Falhas na Janela: {alerta['falhas_janela']} tentativas em <= {JANELA_MINUTOS_BRUTE_FORCE} minutos")
                pdf.cell(0, 4, f"- Total de Falhas deste IP: {alerta['total_falhas_ip']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.set_xy(x_alerta + 5, y_alerta + 12)
                pdf.cell(0, 4, f"- Periodo do Ataque: {alerta['inicio']} ate {alerta['fim']}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.set_xy(x_alerta + 5, y_alerta + 17)
                alvos_str = ", ".join(alerta["utilizadores"][:6])
                if len(alerta["utilizadores"]) > 6:
                    alvos_str += f" e mais {len(alerta['utilizadores']) - 6} contas"
                pdf.cell(0, 4, f"- Contas Visadas: {alvos_str}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

                pdf.set_xy(10, y_alerta + altura_alerta + 3)

        pdf.ln(3)

        # 4. CONTAS BLOQUEADAS (EVENTO 4740)
        if dados["contas_bloqueadas"]:
            # Verifica quebra de página
            if pdf.get_y() > 240:
                pdf.add_page()

            pdf.set_font("helvetica", "B", 11)
            pdf.set_text_color(15, 23, 42)
            pdf.cell(0, 6, "4. Detalhe de Contas Bloqueadas no Sistema (Evento 4740)", new_x=XPos.LMARGIN, new_y=YPos.NEXT)

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

    # Deteta padrões de força bruta
    alertas_brute_force = detetar_padroes_brute_force(dados["falhas_timestamps_por_ip"])

    # Gera o relatório em texto para terminal e ficheiro .txt
    relatorio_texto = gerar_texto_relatorio(dados, alertas_brute_force)
    print("\n" + relatorio_texto)

    # 1. Guarda em .txt
    sucesso_txt, erro_txt = salvar_relatorio_txt(relatorio_texto)
    if sucesso_txt:
        print(f"[+] Relatório em texto guardado em '{FICHEIRO_RELATORIO_TXT}'.")
    else:
        print(f"[-] Erro ao guardar ficheiro .txt: {erro_txt}")

    # 2. Guarda em PDF (se fpdf2 estiver disponível)
    if FPDF_DISPONIVEL:
        sucesso_pdf, erro_pdf = gerar_relatorio_pdf(dados, alertas_brute_force, FICHEIRO_RELATORIO_PDF)
        if sucesso_pdf:
            print(f"[+] Relatório executivo em PDF guardado com sucesso em '{FICHEIRO_RELATORIO_PDF}'.\n")
        else:
            print(f"[-] Erro ao gerar ficheiro PDF: {erro_pdf}\n")
    else:
        print("[i] Dica: Instale 'fpdf2' (pip install fpdf2) para gerar automaticamente o relatório em PDF com alertas coloridos.\n")


if __name__ == "__main__":
    main()
