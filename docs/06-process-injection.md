# 06 — T1055: Process Injection

> **Perspectiva dupla** 🔴🔵. Injecção de processo é executar código no contexto de outro processo — herdando seus privilégios, sua reputação (processo legítimo, frequentemente assinado pela Microsoft) e misturando o comportamento malicioso ao dele. Este documento cobre as variantes em nível **conceitual** e a telemetria que cada uma deixa.

## Por que injetar?

| Motivação | O que o processo alvo oferece |
|---|---|
| Evasão de detecção | Comportamento malicioso vem de processo confiável (explorer, svchost, notepad) |
| Evasão de reputação | SmartScreen/heurística avaliam o executável em disco — o alvo é legítimo |
| Escalação de contexto | Herdar tokens, privilégios e acesso a recursos do alvo |
| Persistência discreta | Código vive em memória alheia, sem novo processo na lista |

## Variantes (visão conceitual)

| Sub-técnica | O que é | Sinal residual clássico |
|---|---|---|
| **T1055.001 — DLL Injection** | Forçar o alvo a carregar uma DLL: escrever o caminho na memória alheia e criar thread remota em `LoadLibrary` | OpenProcess com permissões de escrita/criação de thread + CreateRemoteThread + DLL não assinada carregada (Sysmon EID 7) |
| **T1055.002 — PE Injection** | Copiar um executável inteiro para memória alheia e executá-lo sem passar pelo loader | Memória executável sem arquivo de backing + thread remota |
| **T1055.003 — Thread Execution Hijacking** | Suspender uma thread existente do alvo, redirecionar o contexto (RIP) para código injetado e retomar | SuspendThread/SetThreadContext/ResumeThread cross-process — sequência altamente característica |
| **T1055.004 — APC Injection** | Enfileirar uma Asynchronous Procedure Call na thread alheia, executando quando ela entra em alertable wait | QueueUserAPC cross-process; mais discreto que thread remota, mas igualmente visível a EDR |
| **T1055.012 — Process Hollowing** | Criar processo legítimo suspenso, esvaziar sua imagem e substituir pelo payload antes de rodar | Processo criado em estado suspenso + imagem em memória divergente da imagem em disco (comparação detectável) |
| **T1055.013 — Process Doppelgänging** | Usar transações NTFS para criar imagem "fantasma" em disco que some após o uso | Manipulação transacional de arquivo + processo cujo backing não existe mais; scanners de memória comparam com disco |

## A camada que entrega quase todas: handles cross-process

O elo comum de quase toda injeção: **um processo abre handle em outro com permissões que processos normais raramente precisam**.

| Permissão no handle | Para que serve na injeção | Raridade em software legítimo |
|---|---|---|
| `PROCESS_VM_WRITE` | Escrever payload/caminho na memória alheia | Rara fora de debuggers |
| `PROCESS_VM_OPERATION` | Alocar/mudar proteção de memória alheia | Rara |
| `PROCESS_CREATE_THREAD` | CreateRemoteThread | Muito rara |
| `PROCESS_SET_CONTEXT` | Hijacking de thread | Muito rara |
| Combinação `WRITE + CREATE_THREAD` | Receita clássica completa | Sinal de alta confiança |

Debuggers legítimos (WinDbg, Visual Studio) fazem o mesmo — a defesa trata por **relação pai-filho e prevalência**, não pela permissão isolada.

## Telemetria de detecção

| Fonte | Evento | O que observar |
|---|---|---|
| Sysmon | **EID 8 — CreateRemoteThread** | Processo origem ≠ alvo, especialmente origem não assinada → alvo de sistema |
| Sysmon | **EID 10 — ProcessAccess** | `GrantedAccess` com bits de escrita/thread; origem rara acessando `lsass`, `explorer`, `svchost` |
| Sysmon | EID 7 — ImageLoaded | DLL carregada de path incomum logo após EID 8 |
| Sysmon | EID 1 — ProcessCreate | Hollowing: processo criado suspenso com flags anômalas; linha de comando vs. comportamento divergentes |
| ETW | Threat Intelligence | Alocações executáveis remotas, mudanças de proteção de memória cross-process |
| Scanners de memória | PE-sieve, Moneta (conceitual) | Regiões RWX, imagens em memória que divergem do disco (hollowing/doppelgänging), código sem módulo associado |
| Windows Defender/MDE | Comportamental | Correlação: acesso cross-process + thread remota + execução subsequente |

## Por que EDR moderno captura tanto

1. **O sinal é antigo e estável**: handle com WRITE+CREATE_THREAD em outro processo é anômalo desde sempre — a heurística não envelhece.
2. **Correlação, não evento único**: EID 8 isolado pode ser legítimo; EID 8 + EID 10 + DLL sem assinatura + rede saindo do alvo = cadeia de alta confiança.
3. **Memória denuncia**: scanners comparam imagem em memória vs. disco — hollowing e doppelgänging deixam divergência estrutural.
4. **O alvo colabora**: injetar em processo de sistema torna qualquer comportamento atípico *dele* (rede, filhos) visível por anomalia.

## Trade-offs para o red team autorizado

- Injeção troca visibilidade de **arquivo** por visibilidade de **comportamento** — e comportamento é o que EDR moderno melhor correlaciona.
- Cada variante otimiza um sinal e piora outro: hollowing evita thread remota mas deixa divergência imagem-memória; APC evita CreateRemoteThread mas exige thread em alertable wait (rara no alvo certo).
- No relatório do engajamento: documentar qual sinal residual a variante escolhida deixou — é o que o blue team consegue transformar em regra.

## Contrapartida defensiva

1. **Sysmon com EID 8 e 10 habilitados** (config SwiftOnSecurity/Olaf já cobre) — custo baixo, valor altíssimo.
2. **Regras Sigma**: `proc_access_win_susp_remote_thread`, `win_sysmon_create_remote_thread`, hunting de `GrantedAccess 0x1F0FFF/0x1F3FFF` em alvos sensíveis.
3. **Baselining**: inventariar quais processos legítimos fazem injeção no ambiente (AV, debuggers, DLP) para zerar falsos positivos.
4. **Scanner de memória periódico** em servidores críticos (PE-sieve/Moneta em tarefa agendada, resultados para o SIEM).
5. **Reduzir superfície**: menos serviços com SYSTEM interativo, LSASS como PPL (RunAsPPL) bloqueia a classe inteira contra o lsass.

## Referências

- MITRE ATT&CK: T1055 e sub-técnicas (.001, .002, .003, .004, .012, .013)
- Microsoft Sysmon docs: Event ID 8, 10
- SigmaHQ: regras de `create_remote_thread` e `process_access`
- Relacionado: doc 03 (categorias de evasão), doc 04 (matriz detecção) deste repositório
