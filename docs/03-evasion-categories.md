# 03 — Categorias de evasão (visão conceitual)

> **Escopo**: descrição categórica das classes de técnicas estudadas em red teaming autorizado e CTFs — o "o quê" e o "por que funciona/falha", mapeadas para MITRE ATT&CK. Deliberadamente **sem** código, ferramentas prontas ou receitas operacionais.

## T1027 — Obfuscation (ofuscação)

**Ideia**: mudar a representação do conteúdo sem mudar o comportamento, quebrando padrões estáticos.

| Subcategoria | O que é | Contrapartida da detecção |
|---|---|---|
| Ofuscação de strings | Strings legíveis (IOCs clássicos) codificadas e resolvidas em runtime | Emulação do Defender resolve strings simples; AMSI vê o conteúdo final |
| Ofuscação de script | Renomeação, concatenação, encoding em PowerShell/JS | AMSI recebe o buffer **desofuscado** em camadas — ofuscação de script é das menos eficazes hoje |
| Ofuscação de código nativo | Junk code, reordenação, opaque predicates | Aumenta entropia — e entropia alta é sinal heurístico (trade-off!) |

**Trade-off central**: ofuscar reduz detecção por assinatura, mas aumenta sinais heurísticos. Contra `!ml` (Wacatac), o modelo olha dezenas de features — mudar uma string raramente basta.

## T1027.002 — Packing / crypters (empacotamento)

**Ideia**: envolver o binário em uma camada que o desempacota em memória, escondendo o payload original do scan estático.

- Packers comerciais/legítimos (UPX, Themida, VMProtect) são **conhecidos** — o emulador do Defender desempacota os comuns, e os fortes elevam a suspeita heurística por si só.
- Crypters custom mudam o "casca", mas o comportamento em runtime continua exposto às camadas 4–8 (doc 02).
- Por isso packers respondem por tantos **falsos positivos** Wacatac: a heurística pune a estrutura, não o conteúdo.

## T1140 — Deobfuscate/Decode (codificação em estágios)

**Ideia**: payload armazenado codificado (Base64, XOR, etc.) e decodificado apenas em memória.

- Estático vê apenas dados opacos; em runtime, AMSI/comportamental vê o resultado.
- Em scripts, é a técnica mais trivialmente detectada por AMSI — o buffer final é escaneado de qualquer forma.

## T1620 — Reflective code loading (execução em memória)

**Ideia**: carregar código sem tocar o disco (fileless), negando às camadas 1–3 qualquer alvo.

- Em .NET: carregamento de assemblies via reflexão — passa pela AMSI (.NET instrumentation).
- Em nativo: mapeamento manual de PE em memória — não passa por AMSI clássica, mas deixa marcas comportamentais (alocação RWX, chamadas de API típicas) que EDRs correlacionam.
- É a categoria dominante em CTF/red team moderno — e por isso a mais instrumentada pela defesa atual.

## T1055 — Process injection / hollowing

**Ideia**: executar código no contexto de um processo legítimo, herdando sua reputação e misturando o comportamento.

- Fortemente monitorada: abertura de handle em outro processo com permissões de escrita/execução é um dos sinais comportamentais mais antigos e confiáveis.

## T1218 — Living off the Land (LOLBins)

**Ideia**: usar binários assinados da própria Microsoft (`rundll32`, `mshta`, `regsvr32`, `certutil`, `powershell` etc.) como veículo — nada para assinar/heuristiquear, pois o executável é legítimo.

- A detecção migra de "arquivo" para **linha de comando e relação pai-filho** — território de EDR e regras Sigma.
- Em CTFs, é a categoria mais ensinada porque treina pensar como a defesa.

## T1562.001 — Impair defenses

**Ideia**: reduzir a própria capacidade de detecção (desabilitar AMSI no processo, apagar logs, excluir paths).

- **A mais ruidosa de todas**: alterar estado de segurança gera telemetria própria (Tamper Protection, eventos de alteração de política, alertas de EDR).
- Em engajamentos reais autorizados, costuma exigir privilégio elevado e é onde muitos red teams são pegos.

## T1036 — Masquerading

**Ideia**: parecer legítimo — nome, ícone, metadados, localização e (o mais relevante contra reputação) **assinatura de código**.

- SmartScreen e cloud dão peso grande a assinatura válida e prevalência; mascaramento puro sem reputação tem eficácia limitada contra `!ml`.

## Sandbox/emulator evasion (T1497)

**Ideia**: detectar ambiente de análise (emulador, VM, sandbox) e comportar-se benignamente nele — o emulador do Defender esgota em sleeps/loops, e sandboxes podem ser detectadas por artefatos de ambiente.

- Contrapartida: a camada comportamental no host real não é sandbox — o comportamento malicioso eventualmente aparece onde importa.

## A verdade inconveniente (para ambos os lados)

| Crença comum | Realidade |
|---|---|
| "Ofusquei, passou no VirusTotal" | VirusTotal mede principalmente camadas 1–2; não mede AMSI, comportamental nem EDR no host |
| "Wacatac pegou meu payload, preciso de crypter melhor" | Wacatac `!ml` reage a features estruturais — trocar de packer frequentemente **aumenta** a suspeita |
| "Fileless é indetectável" | Fileless é o vetor mais instrumentado da década (AMSI + ETW) |
| "Evasão é problema de binário" | Evasão moderna é problema de **cadeia**: staging, execução, C2 e comportamento contam juntos |

## Referências

- MITRE ATT&CK: T1027, T1027.002, T1140, T1620, T1055, T1218, T1562.001, T1036, T1497
- Documentação Microsoft: AMSI, cloud-delivered protection, emulador do Defender
- Material público de certificações: OSCP (evasion module), CRTP, Maldev Academy (conceitual)
