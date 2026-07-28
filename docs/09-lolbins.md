# 09 — T1218: LOLBins em Profundidade

> Perspectiva dupla. LOLBin é binário legítimo, assinado pela Microsoft, usado como veículo para comportamento que não era o dele. A técnica quebra o modelo clássico de detecção: não existe arquivo malicioso para assinar, heuristiquear ou colocar em quarentena. O executável é confiável por definição.

## Por que funciona

Toda a pilha de detecção por arquivo (doc 02, camadas 1 a 3 e 7) avalia o executável. Com LOLBin, o executável é `rundll32.exe`, assinado, prevalente, presente em qualquer Windows. O que muda é o contexto: a linha de comando, o processo pai, o que acontece depois. A detecção é obrigada a migrar de identidade para comportamento, e comportamento custa mais caro para analisar.

Tem um bônus para o atacante: nada precisa ser baixado ou gravado. A ferramenta já está lá, em toda máquina, com a assinatura mais confiável do ecossistema.

## As famílias

| Família | Binários típicos | Uso ofensivo conceitual |
|---|---|---|
| Execução de código | `rundll32`, `regsvr32`, `mshta`, `msiexec`, `control` | Executar DLL, scriptlet ou payload sob o nome do binário legítimo |
| Download e transferência | `certutil`, `bitsadmin`, `curl`, `wget` (Windows 10+) | Baixar estágio seguinte com processo confiável |
| Compilação em tempo de execução | `csc`, `msbuild`, `vbc`, `jsc` | Compilar e rodar código sem binário prévio em disco |
| Execução de script e WMI | `wmic`, `powershell`, `cscript`, `msxsl` | Lógica em script sob processo de sistema |
| Bypass de política | `installutil`, `regasm`, `regsvcs`, `msconfig` | Executar código .NET fora do fluxo normal de carregamento |
| Leitura e exfiltração | `findstr`, `forfiles`, `pcalua`, `esentutl` | Copiar, ler ou empacotar dados com ferramenta nativa |

O catálogo completo e mantido pela comunidade é o LOLBAS (lolbas-project.github.io), referência obrigatória para os dois lados.

## Sinais de detecção

Se o arquivo é sempre legítimo, o sinal vive em outro lugar.

| Sinal | Exemplo | Fonte |
|---|---|---|
| Linha de comando anômala | `rundll32` com DLL em pasta de usuário, `certutil` com URL e `-decode` | Sysmon EID 1 |
| Relação pai-filho inusual | Office chamando `mshta`, `winword` gerando `powershell` | Sysmon EID 1, EDR |
| Comportamento de rede | `certutil` ou `bitsadmin` abrindo conexão externa | Sysmon EID 3 |
| Frequência | `csc` ou `msbuild` rodando em estação que não é de desenvolvedor | Inventário, baseline |
| Combinação | LOLBin + flag rara + horário incomum | Correlação no SIEM |

## O problema do falso positivo

A defesa contra LOLBin enfrenta um dilema real: os mesmos binários fazem trabalho legítimo todos os dias. `powershell` é ferramenta de administração, `msbuild` roda em toda máquina de dev, `wmic` aparece em script de inventário. Bloquear tudo quebra o ambiente; não bloquear nada deixa a porta aberta.

A saída madura é por ambiente, não por regra global. Inventariar onde cada LOLBin é legítimo (máquinas de dev, servidores de build, contas de automação) e restringir ou alertar em todo o resto.

## Contrapartida defensiva

1. WDAC ou AppLocker com regras por identidade e caminho. É a única resposta que remove a superfície em vez de persegui-la. Estações de usuário comum não precisam de `msbuild`.
2. Regras Sigma da família `proc_creation_win_lolbin_*`, ajustadas ao baseline do ambiente.
3. Script Block Logging para a família de script: o binário é legítimo, mas o conteúdo executado fica no 4104.
4. Inventário de uso legítimo por função de máquina. Sem baseline, toda regra de LOLBin vira gerador de falso positivo.
5. Correlação de pai-filho no EDR. Office gerando `mshta` ou `rundll32` é das cadeias mais confiáveis que existem.

## Para o red team autorizado

- LOLBin é a primeira técnica que a defesa aprende a caçar depois de assinatura. Assuma regra Sigma no alvo.
- O diferencial de um engajamento maduro é escolher o LOLBin certo para o ambiente: `msbuild` em máquina de dev passa despercebido; em estação de RH, grita.
- No relatório, liste quais binários o ambiente permite sem alerta. É uma das lacunas mais acionáveis que um red team pode entregar, porque a correção (WDAC) é conhecida e barata.

## Referências

- MITRE ATT&CK: T1218 e sub-técnicas (.005, .007, .008, .010, .011)
- LOLBAS: lolbas-project.github.io
- SigmaHQ: família `proc_creation_win_lolbin_*`
- Relacionado neste repositório: doc 02 (pilha de detecção), doc 03 (categorias), doc 04 (matriz de detecção)
