# 01 — O que é o Wacatac

## Nomenclatura das detecções da Microsoft

A Microsoft nomeia detecções no formato `Tipo:Plataforma/Família.Variante!sufixo`:

| Componente | Exemplos | Significado |
|---|---|---|
| Tipo | `Trojan`, `Virus`, `Worm`, `HackTool`, `PUA` | Comportamento classificado |
| Plataforma | `Win32`, `Win64`, `PowerShell`, `JS` | Ambiente alvo |
| Família | `Wacatac`, `Emotet`, `Qakbot` | Família de malware — **ou agrupamento genérico** |
| Variante | `.B`, `.DH`, `.A!1` | Iteração da assinatura |
| Sufixo | `!ml`, `!dha`, `!fnr` | Origem da detecção: ML, heurística avançada, etc. |

## Wacatac é genérico, não uma família

`Trojan:Win32/Wacatac` é uma detecção de **agrupamento** — o Defender aplica quando um arquivo se parece com trojan mas não casa com nenhuma família conhecida específica. Na prática:

- **Não existe "o malware Wacatac"** — arquivos detectados como Wacatac podem ser coisas completamente diferentes entre si.
- O sufixo mais comum é **`B!ml`**: detectado por **modelo de machine learning** (cloud-delivered protection), não por assinatura escrita por analista.
- Detecções `!ml` têm naturalmente **mais falsos positivos** que assinaturas específicas.

## Falsos positivos clássicos

Categorias que disparam Wacatac constantemente:

| Categoria | Por que dispara |
|---|---|
| Cracks, keygens, patches de software | Empacotamento + patching de binário = padrão típico de trojan |
| Binários empacotados (UPX, Themida, VMProtect) | Packers legítimos e maliciosos compartilham estrutura |
| Executáveis de installers menos comuns (NSIS, Inno Setup customizados) | Heurística de dropper/downloader |
| Ferramentas de pentest (versões ofuscadas de utilitários) | Assinaturas de hacktools conhecidos |
| Software assinado com certificado autoassinado ou sem assinatura | Reputação baixa no SmartScreen/cloud |
| Autohotkey/PyInstaller/Go binaries compilados localmente | Entropia alta + import patterns incomuns |

## Como verificar se é falso positivo

1. **VirusTotal** — se só 1-3 engines detectam (e uma é a Microsoft com `!ml`), provável FP.
2. **Microsoft Security Intelligence submission** — portal oficial de submissão para análise de FP.
3. **Análise estática** — DIE (Detect It Easy) para packer, strings, imports, entropia.
4. **Sandbox** — ANY.RUN, Hybrid Analysis, Triage para comportamento real.
5. **Assinatura digital** — validar com `Get-AuthenticodeSignature`.

## Por que isso importa para red team

- Entender que Wacatac é **heurística/ML** (não assinatura exata) explica por que pequenas mudanças estruturais no binário mudam o veredito — e por que "bypassar Wacatac" na verdade significa **"sair da região de decisão do classificador"**, não derrotar uma assinatura específica.
- Detalhamento no doc 03.
