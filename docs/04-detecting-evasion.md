# 04 — Detecção de evasão (Blue Team)

Cada categoria do doc 03 deixa rastro. Este documento é o mapa do outro lado: onde a defesa olha quando o atacante tenta não ser visto.

## Matriz evasão e detecção

| Categoria de evasão | Sinal residual | Telemetria |
|---|---|---|
| Strings ofuscadas (T1027) | Entropia alta, poucas strings legíveis | YARA, análise de entropia, emulação |
| Packing (T1027.002) | Estrutura PE anômala, seções RWX, entrypoint na última seção | Heurística estática, DIE, desempacotamento por emulação |
| Decode em estágios (T1140) | Bloco grande de dados junto de uma função de decode | AMSI no buffer final, análise de fluxo |
| Reflective loading (T1620) | RWX, memória executável sem arquivo de backing | ETW TI, EDR, scanners de memória (PE-sieve, Moneta) |
| Process injection (T1055) | Handle cross-process com escrita e criação de thread | Sysmon EID 8 e 10, regras Sigma |
| LOLBins (T1218) | Linha de comando anômala em binário assinado, pai-filho inusual | Sigma `proc_creation_win_lolbin_*`, AppLocker/WDAC |
| Impair defenses (T1562.001) | Exclusão nova, política alterada, provider mexido | Tamper Protection, eventos 5001/5007, alertas MDE |
| Masquerading (T1036) | Metadados inconsistentes, signer desconhecido, path incomum | SmartScreen, hunting de prevalência |
| Sandbox evasion (T1497) | Sleeps longos, checagem de ambiente | Detonação com tempo acelerado, múltiplas sandboxes |

## Telemetria essencial

| Fonte | O que observar |
|---|---|
| Sysmon | EID 1 (processo, cmdline, hash), 3 (rede), 7 (DLL), 8 (CreateRemoteThread), 10 (ProcessAccess), 11 (arquivo), 13 (registro) |
| Windows Defender | EID 1116 (detecção), 1117 (ação tomada), 5001/5007 (mudança de configuração) |
| AMSI e ETW | Buffers de script, providers de Threat Intelligence |
| PowerShell | EID 4104 (Script Block Logging). Registra o conteúdo final, ofuscado ou não |
| MDE/EDR | Correlação da cadeia: processo, memória, rede, persistência |

## Princípios

1. Nenhuma camada cobre tudo. Assinatura falha contra T1027; AMSI não enxerga nativo; comportamental depende de EDR. Profundidade aqui é literal.
2. Para hunting em script, o 4104 vale mais que a AMSI. A AMSI só fala quando bloqueia; o 4104 conta tudo o que aconteceu.
3. LOLBin se resolve com restrição, não com detecção. AppLocker e WDAC removem a superfície em vez de persegui-la.
4. Tamper Protection ligado transforma T1562.001 em alerta de alta severidade.
5. Memória virou o novo disco. Scan periódico de regiões RWX e imagens divergentes em estações críticas.
6. Arquivo de primeira vista é suspeito até prova contrária. O Block at First Sight existe por um motivo.

## O que isso ensina ao red team autorizado

Passar no Defender não é o objetivo do engajamento. Executar a cadeia sem acionar correlação, é. Sysmon com 4104 já cobre a maioria das categorias desta matriz, então assuma que o alvo tem os dois. E no relatório, diga qual camada foi vencida e qual sinal restou. É essa informação que deixa o blue team melhor do que estava antes de você chegar.
