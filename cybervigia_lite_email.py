#!/usr/bin/env python3
"""
Cyber Vigia Lite - Verificador de E-mail (OSINT)
Python puro - sem dependências externas (roda em CMD, Kali Linux e Termux)

Autor: Cyber Vigia
"""

import re
import socket
import struct
import random
import sys
import hashlib
import json
import urllib.request
import urllib.parse
import urllib.error


# ---------- ETAPA 1: VALIDAÇÃO DE FORMATO ----------

EMAIL_REGEX = re.compile(
    r"^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$"
)


def validar_formato(email):
    """Verifica se o e-mail tem uma sintaxe válida."""
    return bool(EMAIL_REGEX.match(email))


# ---------- ETAPA 2: VALIDAÇÃO DE DOMÍNIO (MX) ----------

def _montar_consulta_dns(dominio, tipo=15):
    transaction_id = random.randint(0, 65535)
    header = struct.pack(">HHHHHH", transaction_id, 0x0100, 1, 0, 0, 0)

    partes = dominio.split(".")
    question = b""
    for parte in partes:
        question += struct.pack("B", len(parte)) + parte.encode()
    question += b"\x00"
    question += struct.pack(">HH", tipo, 1)

    return header + question, transaction_id


def _consultar_dns(dominio, tipo=15, servidor="8.8.8.8", timeout=3):
    pacote, _ = _montar_consulta_dns(dominio, tipo)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(pacote, (servidor, 53))
        resposta, _ = sock.recvfrom(512)
        return resposta
    except socket.timeout:
        return None
    finally:
        sock.close()


def _tem_respostas(resposta_dns):
    if not resposta_dns or len(resposta_dns) < 12:
        return False
    ancount = struct.unpack(">H", resposta_dns[6:8])[0]
    return ancount > 0


def validar_dominio(email, timeout=3):
    try:
        dominio = email.split("@", 1)[1]
    except IndexError:
        return False, "e-mail sem domínio"

    resposta = _consultar_dns(dominio, tipo=15, timeout=timeout)
    if resposta and _tem_respostas(resposta):
        return True, "domínio possui registro MX"

    try:
        socket.getaddrinfo(dominio, None)
        return True, "domínio existe (sem MX, mas resolve)"
    except socket.gaierror:
        return False, "domínio não existe ou não resolve"


# ---------- ETAPA 3: BUSCA EM SITES (ESTILO HOLEHE) ----------

HEADERS_PADRAO = {"User-Agent": "Mozilla/5.0 (CyberVigiaLite)"}


def _get_json(url, timeout=6):
    req = urllib.request.Request(url, headers=HEADERS_PADRAO)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode())


def checar_gravatar(email):
    hash_email = hashlib.md5(email.strip().lower().encode()).hexdigest()
    url = f"https://www.gravatar.com/avatar/{hash_email}?d=404"
    req = urllib.request.Request(url, headers=HEADERS_PADRAO)
    try:
        urllib.request.urlopen(req, timeout=6)
        return True
    except urllib.error.HTTPError as e:
        if e.code == 404:
            return False
        return None
    except Exception:
        return None


def checar_github(email):
    url = f"https://api.github.com/search/users?q={urllib.parse.quote(email)}+in:email"
    try:
        dados = _get_json(url)
        return dados.get("total_count", 0) > 0
    except Exception:
        return None


def checar_duolingo(email):
    url = f"https://www.duolingo.com/2017-06-30/users?email={urllib.parse.quote(email)}"
    try:
        dados = _get_json(url)
        return len(dados.get("users", [])) > 0
    except Exception:
        return None


def buscar_em_sites(email):
    return {
        "Gravatar": checar_gravatar(email),
        "GitHub": checar_github(email),
        "Duolingo": checar_duolingo(email),
    }


def _formatar_resultado(valor):
    if valor is True:
        return "ENCONTRADO"
    if valor is False:
        return "não encontrado"
    return "indisponível (não deu pra checar agora)"


# ---------- RELATÓRIO ----------

def verificar_email(email):
    print(f"\n[ Cyber Vigia Lite ] Verificando: {email}")
    print("-" * 50)

    formato_ok = validar_formato(email)
    print(f"[1] Formato válido ........ {'SIM' if formato_ok else 'NÃO'}")

    if not formato_ok:
        print("-> E-mail com sintaxe inválida, abortando verificação.\n")
        return

    dominio_ok, motivo = validar_dominio(email)
    status = "SIM" if dominio_ok else "NÃO"
    print(f"[2] Domínio válido ........ {status} ({motivo})")

    print("[3] Busca em sites:")
    resultados = buscar_em_sites(email)
    for site, valor in resultados.items():
        print(f"    - {site:<10} ... {_formatar_resultado(valor)}")
    print()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        alvo = sys.argv[1]
    else:
        alvo = input("Digite o e-mail para verificar: ").strip()

    verificar_email(alvo)
