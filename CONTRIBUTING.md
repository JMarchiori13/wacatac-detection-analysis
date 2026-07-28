# Contribuindo com o Wacatac Detection Analysis

Obrigado pelo interesse em contribuir! Este repositório documenta como a detecção do Microsoft Defender funciona e as categorias conceituais de evasão estudadas em **red teaming autorizado e CTFs**, com contrapartida defensiva.

O projeto trabalha com **dupla perspectiva**: 🔴 **Red Team** (categorias de evasão, trade-offs, ATT&CK) e 🔵 **Blue Team** (telemetria, detecção de evasão, hardening).

## Regra de ouro do conteúdo

> **Conceitual, não operacional.** Contribuições descrevem *o que* uma técnica é, *por que* funciona/falha e *como detectá-la* — no nível de material público de certificações (OSCP, CRTP) e blogs de segurança.

❌ **Não serão aceitos**: payloads, crypters/packers prontos, código de bypass funcional de AV/AMSI/ETW, amostras de malware, instruções operacionais de ataque.

## Como contribuir

### 1. Sugerindo conteúdo (Issue)

Abra uma [issue](../../issues/new) com:

- **Tema** — camada de detecção, categoria de evasão, técnica ATT&CK, ferramenta de análise
- **Fonte/evidência** — documentação Microsoft, MITRE ATT&CK, artigo técnico (com link)
- **Perspectiva** — 🔴 ofensiva, 🔵 defensiva ou ambas

### 2. Enviando alterações (Pull Request)

1. Faça fork e crie um branch: `docs/add-<tema>` ou `fix/corrige-<doc>`
2. Mantenha o nível conceitual da regra de ouro
3. Toda técnica ofensiva documentada deve vir **pareada com a detecção** correspondente
4. Commits em português, estilo convencional: `docs: adiciona X`, `fix: corrige Y`
5. Mapeie para MITRE ATT&CK quando aplicável

### 3. Corrigindo erros

O Defender muda rápido (assinaturas diárias, ML em nuvem). Ao corrigir:

- Indique a **data/versão** do Security Intelligence em que verificou
- Se o comportamento varia, documente **ambos** os casos

## Código de conduta

Seja respeitoso e técnico. Este projeto existe para melhorar defensores e treinar red teams autorizados — não para facilitar ataque.

## Dúvidas?

Abra uma issue com a tag `question`.
