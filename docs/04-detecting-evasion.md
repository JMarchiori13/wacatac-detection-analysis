# 04 — Detecção de evasão (Blue Team)

Cada categoria do doc 03 deixa rastros. Este documento é a contrapartida: onde a defesa olha.

## Matriz evasão → detecção

| Categoria de evasão | Sinal residual | Telemetria / regra |
|---|---|---|
| Ofuscação de strings (T1027) | Entropia alta, poucas strings legíveis | YARA estático, análise de entropia, emulação |
| Packing (T1027.002) | Estrutura PE anômala, seções RWX, entrypoint em última seção | Heurística estática, DIE + regras de packer, desempacotamento por emulação |
| Decode em estágios (T1140) | Buffers grandes de dados + função de decode | AMSI (buffer final), análise estática de fluxo |
| Reflective loading (T1620) | Alocação RWX, memória privada executável sem backing de arquivo | ETW, EDR (Sysmon EID 8/10 em alguns casos), scanners de memória (PE-sieve, Moneta) |
| Process injection (T1055) | OpenProcess com VM_WRITE/CREATE_THREAD em processo alheio | Sysmon EID 8 (CreateRemoteThread), EID 10 (ProcessAccess), regras Sigma |
| LOLBins (T1218) | Linha de comando anômala em binário assinado, relação pai-filho inusual | Sigma `proc_creation_win_lolbin_*`, AppLocker/WDAC como prevenção |
| Impair defenses (T1562.001) | Alteração de política AV, exclusões novas, ETW/AMSI tampering | Tamper Protection, eventos 5001/5007 do Defender, alertas MDE |
| Masquerading (T1036) | Metadados inconsistentes, signer desconhecido, path incomum | SmartScreen, regras de signer/path, hunting de prevalência |
| Sandbox evasion (T1497) | Sleep longos, checagens de ambiente | Detonação com aceleração de tempo, múltiplas sandboxes, análise estática da lógica de checagem |

## Telemetria essencial

| Fonte | O que observar |
|---|---|
| Sysmon | EID 1 (processo + cmdline + hash), 3 (rede), 7 (DLL), 8 (CreateRemoteThread), 10 (ProcessAccess), 11 (arquivo), 13 (registro) |
| Windows Defender | EID 1116 (detecção), 1117 (ação), 5001/5007 (config change) |
| AMSI/ETW | Buffers de script, providers de Threat Intelligence |
| PowerShell | EID 4104 (Script Block Logging) — vê **desofuscado**, independente da ofuscação |
| MDE/EDR | Correlação de cadeia: processo → memória → rede → persistência |

## Princípios de defesa contra evasão

1. **Não confie em uma camada**: assinatura falha contra T1027; AMSI não cobre nativo; comportamental precisa de EDR. Defesa em profundidade é literal aqui.
2. **Script Block Logging > AMSI para hunting**: 4104 registra tudo que executou, ofuscado ou não.
3. **LOLBins se resolvem com restrição, não detecção**: AppLocker/WDAC removem a superfície em vez de caçá-la.
4. **Tamper Protection ligado** transforma T1562.001 em alerta de alta severidade.
5. **Memória é o novo disco**: scanners periódicos de RWX/reflective sections em estações críticas.
6. **Prevalência e reputação**: arquivos de primeira vista (BAFS) devem ser tratados como suspeitos até prova contrária em ambientes corporativos.

## Para o red team (authorized): o que isso ensina

- O sucesso de um engajamento não é "passar no Defender" — é executar a cadeia **sem acionar correlação**.
- Telemetria barata (Sysmon + 4104) já cobre a maioria das categorias: assuma que o alvo a tem.
- Relatórios melhores citam **qual camada** foi vencida e qual sinal residual restou — é o que permite o blue team melhorar.
