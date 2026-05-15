"""
Enriquecimento ASN + E-mail + ERP — Supercomm
==============================================
Fontes (em ordem de prioridade):
  ASN  : 1) Base local  2) PeeringDB  3) Registro.br (WHOIS)
  Email: 1) Já existente  2) Registro.br WHOIS (contato técnico/admin)
  ERP  : Inferência via DNS usando domínio do e-mail

Requisitos:
    pip install pandas requests tqdm thefuzz python-Levenshtein

Uso:
    python enriquece_asn_registrobr.py

Entrada : base_isp_enriquecida_pre_consolidacao_BACKUP.csv
          Mailing-ProvedoresTelecom-100k-check_ASN_xlsx_-_asn.csv
Saída   : base_isp_enriquecida_v2.csv
"""

import pandas as pd
import requests
import socket
import subprocess
import re
import time
import shutil
import logging
from pathlib import Path
from tqdm import tqdm
from thefuzz import fuzz

# ─────────────────────────────────────────────
# CONFIGURAÇÃO
# ─────────────────────────────────────────────

ARQUIVO_BASE   = "base_isp_enriquecida_pre_consolidacao_BACKUP.csv"
ARQUIVO_ASN    = "Mailing-ProvedoresTelecom-100k-check_ASN_xlsx_-_asn.csv"
ARQUIVO_BACKUP = "base_isp_v2.BACKUP.csv"
ARQUIVO_SAIDA  = "base_isp_enriquecida_v2.csv"

SCORE_MINIMO        = 85   # score mínimo fuzzy para aceitar match de nome
INTERVALO_PEERINGDB = 0.4  # segundos entre chamadas PeeringDB
INTERVALO_WHOIS     = 1.0  # segundos entre chamadas WHOIS (mais conservador)

PADROES_ERP = {
    "IXC":     ["ixcsoft", "ixcprovedor"],
    "Voalle":  ["voalle"],
    "MK":      ["mkauth", "mksolutions"],
    "SGP":     ["sgpweb", "sgcloud", "sgp."],
    "Atlaz":   ["atlaz"],
    "Hubsoft": ["hubsoft"],
    "Ispfy":   ["ispfy"],
    "Titan":   ["titanerp", "titan.net"],
    "DataTel": ["datatel"],
    "Gestor":  ["gestorpro", "gestorisp"],
    "Nix":     ["nixbr", "nixsolutions"],
}

DOMINIOS_GENERICOS = {
    "gmail.com", "hotmail.com", "yahoo.com", "outlook.com",
    "bol.com.br", "uol.com.br", "terra.com.br", "ig.com.br",
    "live.com", "icloud.com"
}

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("enriquecimento_v2.log", encoding="utf-8"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)


# ─────────────────────────────────────────────
# UTILITÁRIOS
# ─────────────────────────────────────────────

def normalizar_cnpj(v) -> str:
    if pd.isna(v):
        return ""
    return re.sub(r"\D", "", str(v)).zfill(14)


def normalizar_nome(nome) -> str:
    if not nome or pd.isna(nome):
        return ""
    sufixos = [
        r"\bLTDA\.?\b", r"\bS\.?A\.?\b", r"\bEIRELI\b", r"\bME\b", r"\bEPP\b",
        r"\bS\/S\b", r"\bLLC\b", r"\bINC\.?\b", r"\bCOMERCIO\b", r"\bCOMERCIAL\b",
        r"\bSERVICOS\b", r"\bSERVI[ÇC]OS\b", r"\bTELECOMUNICA[ÇC][OÃ]ES\b",
        r"\bTELECOM\b", r"\bPROVEDOR(ES)?\b", r"\bINTERNET\b",
    ]
    nome = str(nome).upper()
    for s in sufixos:
        nome = re.sub(s, "", nome, flags=re.IGNORECASE)
    nome = re.sub(r"[^\w\s]", " ", nome)
    return re.sub(r"\s+", " ", nome).strip()


def vazio(v) -> bool:
    return pd.isna(v) or str(v).strip() in ("", "nan", "None")


def extrair_dominio(email) -> str:
    if vazio(email):
        return ""
    m = re.search(r"@([\w.\-]+)", str(email))
    return m.group(1).lower() if m else ""


def extrair_emails_do_texto(texto: str) -> list:
    """Extrai todos os e-mails de um bloco de texto (ex: saída WHOIS)."""
    return list(set(re.findall(r"[\w.\-+]+@[\w.\-]+\.[a-z]{2,}", texto, re.IGNORECASE)))


# ─────────────────────────────────────────────
# BASE ASN LOCAL
# ─────────────────────────────────────────────

def construir_indice_asn(df_asn: pd.DataFrame) -> list:
    indice = []
    for _, row in df_asn.iterrows():
        nome = str(row.get("NAME", ""))
        asn  = str(row.get("ASN", "")).strip()
        if nome and asn:
            indice.append((normalizar_nome(nome), asn, nome))
    return indice


def match_local(nome: str, indice: list, cache: dict) -> dict:
    nome_norm = normalizar_nome(nome)
    if not nome_norm or nome_norm in cache:
        return cache.get(nome_norm, {})

    melhor_score = 0
    melhor = {}
    for nome_idx, asn, nome_orig in indice:
        score = fuzz.token_sort_ratio(nome_norm, nome_idx)
        if score > melhor_score:
            melhor_score = score
            melhor = {"asn": asn, "nome": nome_orig, "score": score, "fonte": "Base Local"}

    if melhor_score < SCORE_MINIMO:
        melhor = {"asn": "", "nome": melhor.get("nome", ""), "score": melhor_score,
                  "fonte": "Base Local", "motivo": f"Score baixo ({melhor_score})"}

    cache[nome_norm] = melhor
    return melhor


# ─────────────────────────────────────────────
# PEERINGDB
# ─────────────────────────────────────────────

def match_peeringdb(nome: str, cache: dict) -> dict:
    nome_norm = normalizar_nome(nome)
    chave = f"pdb_{nome_norm}"
    if not nome_norm or chave in cache:
        return cache.get(chave, {})

    url = "https://www.peeringdb.com/api/net"
    params = {"name__icontains": nome_norm[:40]}

    try:
        resp = requests.get(url, params=params, timeout=10)
        if resp.status_code != 200:
            cache[chave] = {}
            return {}

        resultados = resp.json().get("data", [])
        if not resultados:
            cache[chave] = {}
            return {}

        melhor_score = 0
        melhor = {}
        for r in resultados:
            score = fuzz.token_sort_ratio(nome_norm, normalizar_nome(r.get("name", "")))
            if score > melhor_score:
                melhor_score = score
                melhor = {
                    "asn":    str(r.get("asn", "")),
                    "nome":   r.get("name", ""),
                    "score":  score,
                    "fonte":  "PeeringDB",
                    "website": r.get("website", ""),
                }

        if melhor_score < SCORE_MINIMO:
            melhor = {"asn": "", "score": melhor_score, "fonte": "PeeringDB",
                      "motivo": f"Score baixo ({melhor_score})"}

        cache[chave] = melhor
        return melhor

    except requests.exceptions.RequestException as e:
        log.debug(f"PeeringDB erro para {nome}: {e}")
        cache[chave] = {}
        return {}


# ─────────────────────────────────────────────
# REGISTRO.BR — WHOIS
# ─────────────────────────────────────────────

def whois_registrobr(query: str) -> str:
    """
    Consulta WHOIS no Registro.br via socket TCP (porta 43).
    Retorna o texto bruto da resposta.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(8)
        s.connect(("whois.registro.br", 43))
        s.sendall((query.strip() + "\r\n").encode("utf-8"))
        resposta = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resposta += chunk
        s.close()
        return resposta.decode("utf-8", errors="replace")
    except Exception as e:
        log.debug(f"WHOIS erro para '{query}': {e}")
        return ""


def extrair_asn_do_whois(texto: str) -> str:
    """Extrai número ASN de resposta WHOIS do Registro.br."""
    m = re.search(r"aut-num:\s*(AS\d+)", texto, re.IGNORECASE)
    return m.group(1) if m else ""


def extrair_email_do_whois(texto: str) -> list:
    """Extrai e-mails de contato técnico/admin do WHOIS."""
    emails = extrair_emails_do_texto(texto)
    # Filtra e-mails genéricos de abuse/noreply
    ignorar = {"abuse", "noreply", "no-reply", "postmaster", "hostmaster"}
    return [e for e in emails if not any(p in e.lower() for p in ignorar)]


def buscar_registrobr_por_nome(nome: str, cache: dict) -> dict:
    """
    Tenta localizar ASN e e-mail no Registro.br buscando por nome da organização.
    Estratégia: busca por razão social simplificada.
    """
    nome_norm = normalizar_nome(nome)
    chave = f"rbr_{nome_norm}"
    if not nome_norm or chave in cache:
        return cache.get(chave, {})

    # Tenta os primeiros tokens do nome (Registro.br aceita busca parcial)
    tokens = nome_norm.split()[:3]
    query = " ".join(tokens)

    texto = whois_registrobr(query)
    time.sleep(INTERVALO_WHOIS)

    resultado = {}
    if texto and "%" not in texto[:20]:  # linhas começando com % = sem resultado
        asn    = extrair_asn_do_whois(texto)
        emails = extrair_email_do_whois(texto)
        if asn:
            resultado["asn"]   = asn
            resultado["fonte"] = "Registro.br"
            resultado["score"] = 70  # score fixo — sem fuzzy, validação manual recomendada
        if emails:
            resultado["emails"] = emails

    cache[chave] = resultado
    return resultado


def buscar_email_por_dominio_registrobr(dominio: str, cache: dict) -> list:
    """
    Consulta WHOIS do domínio no Registro.br para extrair e-mail de contato.
    """
    if not dominio or dominio in DOMINIOS_GENERICOS:
        return []
    chave = f"dom_{dominio}"
    if chave in cache:
        return cache.get(chave, [])

    texto = whois_registrobr(dominio)
    time.sleep(INTERVALO_WHOIS)

    emails = extrair_email_do_whois(texto)
    cache[chave] = emails
    return emails


# ─────────────────────────────────────────────
# ERP — INFERÊNCIA VIA DNS
# ─────────────────────────────────────────────

def inferir_erp(dominio: str, cache: dict) -> tuple:
    if not dominio or dominio in DOMINIOS_GENERICOS:
        return "", ""
    if dominio in cache:
        return cache[dominio]

    for erp, padroes in PADROES_ERP.items():
        for padrao in padroes:
            # Padrão contido no próprio domínio
            if padrao.rstrip(".") in dominio:
                cache[dominio] = (erp, f"domínio contém '{padrao}'")
                return cache[dominio]
            # Testa subdomínio via DNS
            host = f"{padrao.rstrip('.')}.{dominio}"
            # Valida host antes de consultar: sem partes vazias, sem caracteres inválidos
            partes = host.split(".")
            if any(p == "" for p in partes) or len(partes) < 2:
                continue
            try:
                socket.setdefaulttimeout(2)
                socket.gethostbyname(host)
                cache[dominio] = (erp, f"subdomínio resolvido: {host}")
                return cache[dominio]
            except (socket.herror, socket.gaierror, socket.timeout, UnicodeError):
                continue

    cache[dominio] = ("", "")
    return "", ""


# ─────────────────────────────────────────────
# PIPELINE PRINCIPAL
# ─────────────────────────────────────────────

def main():
    log.info("=" * 60)
    log.info("Enriquecimento ASN + E-mail + ERP — v2")
    log.info("=" * 60)

    # ── Verificar arquivos ─────────────────────────────────────────
    for arq in [ARQUIVO_BASE, ARQUIVO_ASN]:
        if not Path(arq).exists():
            log.error(f"Arquivo não encontrado: {arq}")
            return

    shutil.copy(ARQUIVO_BASE, ARQUIVO_BACKUP)
    log.info(f"Backup: {ARQUIVO_BACKUP}")

    # ── Carregar base ──────────────────────────────────────────────
    base = pd.read_csv(ARQUIVO_BASE, dtype=str, encoding="utf-8-sig")
    log.info(f"Base: {len(base):,} registros | {len(base.columns)} colunas")

    # ── Detectar colunas chave ─────────────────────────────────────
    col_nome = next(
        (c for c in base.columns if "nome" in c.lower() and "entidade" in c.lower()),
        next((c for c in base.columns if "razaosocial" in c.lower().replace(" ", "").replace("_", "")), None)
    )
    col_asn   = next((c for c in base.columns if c.lower() == "asn"), None)
    col_erp   = next((c for c in base.columns if c.lower() == "erp"), None)
    col_email = next(
        (c for c in ["Email_Consolidado", "ML_EnderecoEletronico", "API_Email"] if c in base.columns),
        None
    )

    log.info(f"Colunas: nome='{col_nome}' | asn='{col_asn}' | erp='{col_erp}' | email='{col_email}'")

    if not col_nome:
        log.error("Coluna de nome não encontrada. Verifique o CSV.")
        return

    # Criar colunas de resultado se não existirem
    novas_colunas = [
        "ASN_Encontrado", "ASN_Fonte", "ASN_Score", "ASN_Motivo",
        "Email_WHOIS", "ERP_Inferido", "ERP_Evidencia"
    ]
    for col in novas_colunas:
        if col not in base.columns:
            base[col] = ""

    # ── Carregar base ASN local ────────────────────────────────────
    log.info("")
    log.info("── Carregando base ASN local ──")
    df_asn = pd.read_csv(ARQUIVO_ASN, dtype=str, encoding="utf-8-sig")
    df_asn = df_asn[[c for c in df_asn.columns if not c.startswith("Unnamed")]]
    indice_asn = construir_indice_asn(df_asn)
    log.info(f"  {len(indice_asn):,} entradas indexadas")

    # ── Identificar registros que precisam de enriquecimento ───────
    sem_asn = base[
        col_asn if col_asn else "ASN_Encontrado"
    ].apply(lambda v: vazio(v)).values

    sem_erp = base[col_erp].apply(vazio).values if col_erp else [True] * len(base)

    sem_email = base[col_email].apply(vazio).values if col_email else [True] * len(base)

    log.info(f"Sem ASN:   {sem_asn.sum():,}")
    log.info(f"Sem ERP:   {sem_erp.sum():,}")
    log.info(f"Sem e-mail:{sem_email.sum():,}")

    # ── Caches compartilhados ──────────────────────────────────────
    cache_local = {}
    cache_pdb   = {}
    cache_rbr   = {}
    cache_dns   = {}

    # ── Loop principal ─────────────────────────────────────────────
    log.info("")
    log.info("── Processando registros ──")

    precisa_processar = sem_asn | sem_erp | sem_email
    indices = [i for i, v in enumerate(precisa_processar) if v]
    log.info(f"Registros a processar: {len(indices):,}")
    log.info(f"Estimativa de tempo: ~{len(indices) * 2 / 60:.0f}–{len(indices) * 4 / 60:.0f} minutos")

    asn_local_count = asn_pdb_count = asn_rbr_count = 0
    email_whois_count = erp_count = 0

    for i in tqdm(indices, desc="Enriquecendo", unit="registro"):
        row  = base.iloc[i]
        nome = str(row.get(col_nome, ""))

        # ── ASN ────────────────────────────────────────────────────
        if sem_asn[i]:
            asn_resultado = {}

            # 1) Base local
            r = match_local(nome, indice_asn, cache_local)
            if r.get("asn"):
                asn_resultado = r
                asn_local_count += 1

            # 2) PeeringDB
            if not asn_resultado.get("asn"):
                r = match_peeringdb(nome, cache_pdb)
                time.sleep(INTERVALO_PEERINGDB)
                if r.get("asn"):
                    asn_resultado = r
                    asn_pdb_count += 1

            # 3) Registro.br
            if not asn_resultado.get("asn"):
                r = buscar_registrobr_por_nome(nome, cache_rbr)
                if r.get("asn"):
                    asn_resultado = r
                    asn_rbr_count += 1

            if asn_resultado.get("asn"):
                base.at[base.index[i], "ASN_Encontrado"] = str(asn_resultado.get("asn", ""))
                base.at[base.index[i], "ASN_Fonte"]      = str(asn_resultado.get("fonte", ""))
                base.at[base.index[i], "ASN_Score"]      = str(asn_resultado.get("score", ""))
            elif asn_resultado.get("motivo"):
                base.at[base.index[i], "ASN_Motivo"] = str(asn_resultado.get("motivo", ""))

        # ── E-mail via WHOIS do domínio ────────────────────────────
        dominio = ""
        if col_email:
            dominio = extrair_dominio(str(row.get(col_email, "")))

        # Tenta também extrair domínio do e-mail da API se disponível
        if not dominio and "API_Email" in base.columns:
            dominio = extrair_dominio(str(row.get("API_Email", "")))

        if sem_email[i] and dominio:
            emails = buscar_email_por_dominio_registrobr(dominio, cache_rbr)
            if emails:
                base.at[base.index[i], "Email_WHOIS"] = "; ".join(emails)
                email_whois_count += 1

        # ── ERP via DNS ────────────────────────────────────────────
        if sem_erp[i] and dominio:
            erp, evidencia = inferir_erp(dominio, cache_dns)
            if erp:
                base.at[base.index[i], "ERP_Inferido"]  = erp
                base.at[base.index[i], "ERP_Evidencia"] = evidencia
                erp_count += 1

    # ── Resumo ─────────────────────────────────────────────────────
    log.info("")
    log.info("── Resumo ──")
    log.info(f"  ASN via Base Local : {asn_local_count:,}")
    log.info(f"  ASN via PeeringDB  : {asn_pdb_count:,}")
    log.info(f"  ASN via Registro.br: {asn_rbr_count:,}")
    log.info(f"  E-mail via WHOIS   : {email_whois_count:,}")
    log.info(f"  ERP inferido       : {erp_count:,}")

    # ── Reordenar colunas ──────────────────────────────────────────
    colunas_novas  = ["ASN_Encontrado", "ASN_Fonte", "ASN_Score", "ASN_Motivo",
                      "Email_WHOIS", "ERP_Inferido", "ERP_Evidencia"]
    colunas_base   = [c for c in base.columns if c not in colunas_novas]
    base = base[colunas_base + colunas_novas]

    # ── Exportar ───────────────────────────────────────────────────
    base.to_csv(ARQUIVO_SAIDA, index=False, encoding="utf-8-sig")

    log.info("")
    log.info(f"✓ Exportado: {ARQUIVO_SAIDA}")
    log.info(f"  Registros : {len(base):,}")
    log.info(f"  Colunas   : {len(base.columns)}")
    log.info("=" * 60)
    log.info("Concluído.")


if __name__ == "__main__":
    main()
