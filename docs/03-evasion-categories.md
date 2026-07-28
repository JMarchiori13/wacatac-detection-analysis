# 03 — Categorias de evasão (visão conceitual)

> Escopo: descrição das classes de técnicas estudadas em red teaming autorizado e CTFs. O que cada uma é, por que funciona, por que falha, e onde fica no MITRE ATT&CK. Sem código, sem ferramenta pronta, sem receita.

## T1027 — Obfuscation

Mudar a representação sem mudar o comportamento, para quebrar padrões estáticos.

| Subcategoria | O que é | Como a detecção responde |
|---|---|---|
| Strings ofuscadas | IOCs clássicos codificados e resolvidos em runtime | O emulador resolve strings simples; a AMSI vê o conteúdo final |
| Script ofuscado | Renomeação, concatenação, encoding | A AMSI recebe o buffer desofuscado, em camadas. Das técnicas mais desgastadas hoje |
| Código nativo ofuscado | Junk code, reordenação, opaque predicates | Aumenta entropia, e entropia alta é sinal heurístico. A técnica cobra pedágio dela mesma |

O trade-off central da categoria: ofuscar reduz detecção por assinatura e aumenta sinais heurísticos na mesma medida. Contra um classificador de ML como o Wacatac, que pesa dezenas de features, trocar uma string raramente move o veredito.

## T1027.002 — Packing e crypters

Envolver o binário numa casca que o desempacota em memória, escondendo o payload do scan estático.

Packers conhecidos (UPX, Themida, VMProtect) são território mapeado: o emulador abre os simples, e os fortes elevam a suspeita só por estarem ali. Crypters custom trocam a casca, mas o comportamento em runtime continua exposto às camadas 4 a 8 do doc 02. Não por acaso, packers lideram os falsos positivos de Wacatac. A heurística pune a estrutura, não o conteúdo.

## T1140 — Deobfuscate/Decode

Payload armazenado codificado (Base64, XOR e similares) e decodificado só em memória. O scan estático vê dados opacos; a AMSI e o comportamental veem o resultado. Em script, é a técnica mais trivialmente detectada que existe, porque o buffer final é escaneado de qualquer jeito.

## T1620 — Reflective code loading

Carregar código sem tocar o disco, negando alvo às camadas 1 a 3. Em .NET o caminho passa pela AMSI; em nativo, exige um loader manual que deixa marcas de memória próprias. É a categoria dominante em CTF e red team moderno, e por isso a mais instrumentada pela defesa. O doc 07 inteiro é sobre ela.

## T1055 — Process injection

Executar código dentro de um processo legítimo, herdando reputação e misturando comportamento. O sinal é antigo: abrir handle em outro processo com permissão de escrita e criação de thread é anomalia confiável faz décadas. Detalhes no doc 06.

## T1218 — Living off the Land

Usar binários assinados da própria Microsoft como veículo: `rundll32`, `mshta`, `regsvr32`, `certutil`, `powershell`. Não há arquivo suspeito para assinar ou heuristiquear, porque o executável é legítimo. A detecção migra para linha de comando e relação pai-filho, território de EDR e Sigma. É a categoria mais ensinada em CTFs porque obriga a pensar como a defesa.

## T1562.001 — Impair defenses

Reduzir a capacidade de detecção: desabilitar AMSI no processo, apagar logs, criar exclusões. A categoria mais barulhenta de todas. Alterar estado de segurança gera telemetria própria, entre Tamper Protection, eventos de mudança de política e alertas de EDR. Em engajamento real costuma exigir privilégio alto, e é onde muitos red teams são pegos.

## T1036 — Masquerading

Parecer legítimo: nome, ícone, metadados, localização e, o que pesa mais contra reputação, assinatura de código. SmartScreen e nuvem dão peso grande a assinatura válida e prevalência. Mascaramento sem reputação tem eficácia limitada contra ML.

## T1497 — Sandbox e emulator evasion

Detectar ambiente de análise e fingir ser benigno nele. O emulador do Defender esgota em sleeps e loops; sandboxes vazam artefatos de ambiente. A resposta da defesa é que a camada comportamental no host real não é sandbox. Cedo ou tarde o comportamento aparece onde importa.

## Verdades inconvenientes para os dois lados

| Crença comum | Realidade |
|---|---|
| "Ofusquei e passou no VirusTotal" | VirusTotal mede principalmente as camadas 1 e 2. Não mede AMSI, comportamental nem EDR |
| "Preciso de um crypter melhor" | Wacatac `!ml` reage a features estruturais. Trocar de packer com frequência aumenta a suspeita |
| "Fileless é indetectável" | Fileless é o vetor mais instrumentado da década |
| "Evasão é problema de binário" | Evasão moderna é problema de cadeia: staging, execução, C2 e comportamento contam juntos |

## Referências

- MITRE ATT&CK: T1027, T1027.002, T1140, T1620, T1055, T1218, T1562.001, T1036, T1497
- Documentação Microsoft: AMSI, cloud-delivered protection, emulador do Defender
- Material público de certificações: OSCP, CRTP, Maldev Academy (nível conceitual)
