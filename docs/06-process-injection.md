# 06 — T1055: Process Injection

> Perspectiva dupla, ofensiva e defensiva. Process injection é executar código no contexto de outro processo. O código herda os privilégios do alvo, a reputação dele (frequentemente um binário assinado pela Microsoft) e ainda dilui o próprio comportamento no comportamento normal do hospedeiro.

## Por que injetar

| Motivação | O que o processo alvo oferece |
|---|---|
| Evasão de detecção | O comportamento malicioso sai de um processo confiável |
| Evasão de reputação | SmartScreen e heurística avaliam o executável em disco, e o alvo é legítimo |
| Contexto | Tokens, privilégios e acessos do alvo |
| Discrição | Código em memória alheia, sem processo novo na lista |

## Variantes

| Sub-técnica | O que é | Sinal residual |
|---|---|---|
| T1055.001 — DLL Injection | Escrever o caminho da DLL na memória alheia e criar thread remota em `LoadLibrary` | Handle com escrita e criação de thread, mais DLL não assinada carregada (EID 7) |
| T1055.002 — PE Injection | Copiar um executável inteiro para memória alheia sem passar pelo loader | Memória executável sem arquivo de imagem associado |
| T1055.003 — Thread Hijacking | Suspender uma thread do alvo, redirecionar o contexto e retomar | Sequência Suspend/SetContext/Resume cross-process, muito característica |
| T1055.004 — APC Injection | Enfileirar uma chamada assíncrona na thread alheia | QueueUserAPC cross-process; discreto, mas visível a EDR |
| T1055.012 — Process Hollowing | Criar processo legítimo suspenso, esvaziar a imagem e substituir pelo payload | Processo suspenso na criação e divergência entre imagem em memória e em disco |
| T1055.013 — Doppelgänging | Usar transação NTFS para criar imagem fantasma que some depois do uso | Processo cujo backing não existe mais; scanner de memória compara com disco |

## O elo comum: handles cross-process

Quase toda injeção passa pelo mesmo gesto: um processo abre handle em outro com permissões que software normal quase nunca pede.

| Permissão | Para que serve na injeção | Em software legítimo |
|---|---|---|
| `PROCESS_VM_WRITE` | Escrever o payload na memória alheia | Rara fora de debuggers |
| `PROCESS_VM_OPERATION` | Alocar e mudar proteção de memória | Rara |
| `PROCESS_CREATE_THREAD` | CreateRemoteThread | Muito rara |
| `PROCESS_SET_CONTEXT` | Hijacking de thread | Muito rara |
| WRITE + CREATE_THREAD juntas | A receita clássica completa | Sinal de alta confiança |

Debuggers fazem a mesma coisa, então a defesa não olha a permissão sozinha. Olha quem abriu o handle em quem, e com que frequência aquilo acontece no ambiente.

## Telemetria

| Fonte | Evento | O que observar |
|---|---|---|
| Sysmon | EID 8 — CreateRemoteThread | Origem não assinada criando thread em processo de sistema |
| Sysmon | EID 10 — ProcessAccess | `GrantedAccess` com bits de escrita e thread; origem rara acessando `lsass`, `explorer`, `svchost` |
| Sysmon | EID 7 — ImageLoaded | DLL de path incomum logo depois de um EID 8 |
| Sysmon | EID 1 — ProcessCreate | Hollowing: processo criado suspenso, cmdline e comportamento divergindo |
| ETW | Threat Intelligence | Alocação executável remota, mudança de proteção cross-process |
| Scanners de memória | PE-sieve, Moneta | Regiões RWX, imagens que divergem do disco, código sem módulo |
| Defender/MDE | Comportamental | Acesso cross-process seguido de thread remota e execução |

## Por que EDR captura tanto

O sinal é antigo e estável. Handle com escrita e criação de thread em processo alheio é anomalia desde sempre, e heurística assim não envelhece. Além disso, ninguém olha o evento isolado: EID 8 sozinho pode ser legítimo, mas EID 8 com EID 10, DLL sem assinatura e conexão de rede saindo do alvo formam uma cadeia de confiança alta. E por fim, a memória denuncia. Scanners comparam o que está na memória com o que está no disco, e hollowing deixa divergência estrutural.

Tem um detalhe irônico: injetar num processo de sistema faz qualquer comportamento atípico *dele* (rede, processo filho) saltar aos olhos por anomalia. O hospedeiro confiável vira delator.

## Trade-offs para o red team autorizado

Injeção troca visibilidade de arquivo por visibilidade de comportamento, e comportamento é exatamente o que EDR moderno melhor correlaciona. Cada variante otimiza um sinal e piora outro: hollowing evita thread remota mas deixa divergência na imagem; APC evita CreateRemoteThread mas precisa de uma thread em alertable wait, que não existe em todo alvo. No relatório, registre qual sinal a variante escolhida deixou. É isso que vira regra de detecção depois.

## Contrapartida defensiva

1. Sysmon com EID 8 e 10 habilitados. Custo baixo, retorno imediato.
2. Regras Sigma de `create_remote_thread` e `process_access`, mais hunting de `GrantedAccess` altos em alvos sensíveis.
3. Baseline do que injeta legitimamente no ambiente (AV, debuggers, DLP), para o falso positivo não esconder o positivo.
4. Scanner de memória agendado em servidores críticos, com resultados no SIEM.
5. LSASS como PPL (RunAsPPL). Elimina a classe inteira contra o processo mais visado.

## Referências

- MITRE ATT&CK: T1055 e sub-técnicas (.001, .002, .003, .004, .012, .013)
- Microsoft: documentação do Sysmon, eventos 8 e 10
- SigmaHQ: regras de `create_remote_thread` e `process_access`
- Relacionado neste repositório: doc 03 (categorias), doc 04 (matriz de detecção), doc 07 (reflective loading)
