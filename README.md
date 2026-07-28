# Wacatac Detection Analysis

Análise técnica da detecção **`Trojan:Win32/Wacatac`** do Microsoft Defender: o que ela é, por que dispara (inclusive em falsos positivos), como o mecanismo de detecção funciona e quais **categorias conceituais de evasão** são estudadas em **red teaming autorizado e CTFs** — sempre com a contrapartida defensiva.

> **Propósito**: referência para red teams em engajamentos **autorizados** (pentest, CTF, emulação de adversário) e blue teams que precisam entender o que estão detectando. Nenhum conteúdo aqui é payload, crypter pronto ou código de bypass — as técnicas são descritas em nível **conceitual**, como em material público de certificações (OSCP, CRTP) e blogs de segurança. Uso fora de ambientes autorizados é ilegal.

---

## TL;DR

| Pergunta | Resposta |
|---|---|
| O que é Wacatac? | Nome de detecção **genérica/heurística** do Microsoft Defender — não uma família específica de malware |
| Por que meu arquivo foi detectado? | Assinatura genérica, heurística de empacotamento, ou modelo de ML (`!ml` no nome) |
| É sempre malware real? | **Não** — é um dos falsos positivos mais comuns em cracks, keygens, packers e binários obscuros |
| O que `B!ml` significa? | Variante detectada por **machine learning em nuvem**, não por assinatura estática |
| Evasão é tópico legítimo? | Sim, em escopo autorizado (pentest/CTF) — é parte do currículo de OSCP/CRTP e da emulação de adversário |

---

## Documentos

1. **[O que é o Wacatac](docs/01-what-is-wacatac.md)** — nomenclatura do Defender, por que é genérico, falsos positivos comuns.
2. **[Como o Defender detecta](docs/02-how-defender-detects.md)** — assinaturas, heurística, AMSI, ETW, cloud ML, SmartScreen.
3. **[Categorias de evasão (conceitual)](docs/03-evasion-categories.md)** — as classes de técnicas estudadas em red team autorizado, mapeadas para MITRE ATT&CK, sem código operacional.
4. **[Detecção de evasão (Blue Team)](docs/04-detecting-evasion.md)** — como a defesa pega cada categoria, telemetria e hardening.
5. **[Lab de CTF autorizado](docs/05-ctf-lab-setup.md)** — como montar um ambiente isolado e legal para estudar detecção/evasão.
6. **[T1055 — Process Injection](docs/06-process-injection.md)** 🔴🔵 — variantes (DLL, PE, hijacking, APC, hollowing, doppelgänging), handles cross-process e telemetria de detecção.
7. **[T1620 — Reflective Code Loading](docs/07-reflective-loading.md)** 🔴🔵 — fileless em .NET (via AMSI) e nativo (loader manual), sinais de memória e contrapartida defensiva.

---

## Linha editorial

✅ **Neste repo**: como a detecção funciona, categorias e trade-offs das técnicas de evasão, como a defesa responde, referências ATT&CK, setup de lab.

❌ **Fora do escopo**: payloads, crypters prontos, código de bypass funcional, instruções para atacar sistemas sem autorização.

## Aviso legal

Evasão de antivírus é uma disciplina legítima **somente** dentro de autorização formal (contrato de pentest, regras de CTF, lab próprio). Fora desse contexto, viola legislações como a Lei Carolina Dieckmann (BR), CFAA (US) e equivalentes.
