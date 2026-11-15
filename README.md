# Cyber Vigia Lite 🦉

Ferramenta de OSINT (codigo aberto) para verificacao de e-mail - feita em Python puro, sem nenhuma biblioteca externa. Roda igual em CMD (Windows), Kali Linux e Termux (Android).

Projeto da Cyber Vigia.

## O que ela faz

Dado um e-mail, a ferramenta roda 3 verificacoes:

1. Validacao de formato - confere se a sintaxe do e-mail e valida.
2. Validacao de dominio (MX) - consulta DNS (feita manualmente via socket, sem dnspython) pra conferir se o dominio existe e recebe e-mails.
3. Busca em sites - verifica se o e-mail esta cadastrado em alguns servicos publicos: Gravatar, GitHub, Duolingo.

## Requisitos

- Python 3.8 ou superior
- Nenhuma instalacao adicional (pip install) necessaria - usa so a biblioteca padrao do Python

## Como usar

Clone o repositorio:

git clone https://github.com/alairon330-rgb/cybervigia-lite.git
cd cybervigia-lite

Rode o script passando o e-mail como argumento:

python cybervigia_lite_email.py exemplo@gmail.com

Ou rode sem argumento e digite o e-mail quando for pedido:

python cybervigia_lite_email.py

## Aviso de uso etico

Esta ferramenta foi feita para fins educacionais e de investigacao OSINT etica. Use com responsabilidade e sempre dentro da lei.

## Contribua

Pull requests sao bem-vindos!

---

Feito com carinho por Cyber Vigia
