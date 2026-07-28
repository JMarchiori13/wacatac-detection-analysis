# 01 — O que é o Wacatac

## Nomenclatura das detecções da Microsoft

A Microsoft nomeia detecções no formato `Tipo:Plataforma/Família.Variante!sufixo`:

| Componente | Exemplos | Significado |
|---|---|---|
| Tipo | `Trojan`, `Virus`, `Worm`, `HackTool`, `PUA` | Comportamento classificado |
| Plataforma | `Win32`, `Win64`, `PowerShell`, `JS` | Ambiente alvo |
| Família | `Wacatac`, `Emotet`, `Qakbot` | Família de malware, ou um agrupamento genérico |
| Variante | `.B`, `.DH`, `.A!1` | Iteração da assinatura |
| Sufixo | `!ml`, `!dha`, `!fnr` | Origem da detecção: ML, heurística avançada e assim por diante |

## Wacatac é um agrupamento, não uma família

`Trojan:Win32/Wacatac` é o nome que o Defender dá quando um arquivo parece trojan mas não bate com nenhuma família conhecida. Duas consequências disso:

- Não existe "o malware Wacatac". Dois arquivos detectados com esse nome podem não ter nada em comum.
- O sufixo mais comum é `B!ml`, que indica veredito de machine learning em nuvem, e não uma assinatura escrita por um analista. Detecções de ML erram para o lado do exagero com mais frequência que assinaturas específicas.

## Falsos positivos clássicos

| Categoria | Por que dispara |
|---|---|
| Cracks, keygens, patches | Empacotamento somado a patching de binário é a cara de um trojan |
| Binários com UPX, Themida, VMProtect | Packers legítimos e maliciosos compartilham a mesma estrutura |
| Installers de NSIS ou Inno Setup customizados | Heurística de dropper/downloader |
| Ferramentas de pentest ofuscadas | Vizinhança com hacktools conhecidos |
| Executáveis sem assinatura ou com certificado autoassinado | Reputação baixa no SmartScreen e na nuvem |
| Builds locais de AutoHotkey, PyInstaller, Go | Entropia alta e padrão de imports fora do comum |

## Como checar se é falso positivo

1. VirusTotal. Se só uma ou três engines acusam, e uma delas é a Microsoft com `!ml`, a chance de FP é alta.
2. Portal de submissão do Microsoft Security Intelligence, que é o canal oficial para contestar.
3. Análise estática: DIE para identificar packer, strings, imports e entropia.
4. Sandbox: ANY.RUN, Hybrid Analysis ou Triage mostram o comportamento real.
5. `Get-AuthenticodeSignature` para validar a assinatura digital.

## Por que isso importa para o red team

Wacatac ser heurística de ML, e não assinatura exata, muda a leitura do problema. Não existe um padrão de bytes para derrotar. O que existe é uma região de decisão de um classificador, e sair dela é um problema diferente de enganar uma assinatura. O doc 03 desenvolve esse ponto.
