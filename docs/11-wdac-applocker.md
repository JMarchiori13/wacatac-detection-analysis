# 11 — WDAC e AppLocker: Whitelisting e suas Falhas Conceituais

> Perspectiva dupla. O doc 09 apresentou WDAC e AppLocker como a resposta que remove a superfície de LOLBins. Este documento conta o resto da história: por que whitelisting quase nunca é implantado direito, e o que um red team encontra quando encontra.

## O que cada um é

| | AppLocker | WDAC (Windows Defender Application Control) |
|---|---|---|
| Geração | Windows 7 em diante | Windows 10 1903+ (evolução do Device Guard) |
| Escopo | Executáveis, scripts, DLLs, MSI, packaged apps | Mesmo escopo, mais drivers de kernel |
| Modelo | Regras por publisher, path, hash | Políticas XML por publisher, path, hash, reputação |
| Posição da Microsoft | Mantido, sem evolução | Caminho estratégico atual |

A ideia dos dois é a mesma: inverter o modelo de defesa. Em vez de listar o que é malicioso (antivírus), listar o que é permitido e negar todo o resto.

## Por que a implantação real é quase sempre fraca

Teoria linda, prática difícil. Os padrões que aparecem em engajamento:

| Falha de implantação | O que o red team encontra |
|---|---|
| Modo audit-only eterno | A política existe, registra violações, não bloqueia nada. Comum demais |
| Regra de path larga | `C:\Windows\*` e `C:\Program Files\*` permitidos inteiros, incluindo subpastas graváveis pelo usuário |
| Exceções acumuladas | Anos de "libera só esse app" até a política virar queijo suíço |
| Sem cobertura de script | Executável bloqueado, PowerShell livre |
| Sem política de DLL | Bloqueio de exe, sideload livre |
| Default allow para admin | Administrador local desliga a política no próprio host |

A lição defensiva é incômoda mas verdadeira: whitelisting mal implantado é pior que nenhum, porque gera a sensação de controle sem o controle.

## Categorias conceituais de contorno

Mesmo bem implantado, o modelo tem fraquezas estruturais conhecidas:

### Abuso do permitido (o caso LOLBin)

Se a política permite `msbuild`, `csc` ou `powershell` porque o ambiente precisa deles, o atacante usa exatamente esses. É o doc 09 aplicado: o contorno não quebra a política, obedece a ela. A defesa correspondente é regra por path e publisher, e não só por nome de binário.

### Escrita em path permitido

Política baseada em path só funciona se o usuário não escreve no path permitido. Uma subpasta gravável dentro de `C:\Windows` ou de um diretório de programa permitido transforma a regra de path em convite. Auditoria de permissão de escrita nos paths permitidos é item obrigatório de checklist.

### Execução por componente confiável

O Windows é cheio de mecanismos legítimos de execução indireta: COM, serviços, tarefas, WMI, extensões de shell. Uma política que cobre executáveis mas não cobre quem os chama deixa caminhos indiretos abertos. Por isso WDAC moderno cobre scripts, DLLs e drivers, e não só exe.

### Assinatura mal escopada

Regra que permite tudo assinado pela Microsoft, sem refinamento, abre a porta para todo LOLBin de uma vez. Regra por publisher precisa de granularidade: assinado pela Microsoft *e* produto específico, ou *e* caminho específico.

## Os eventos que a defesa precisa olhar

| Fonte | Evento | Significado |
|---|---|---|
| AppLocker | 8003/8004 (audit/block de exe), 8006/8007 (script) | Tentativas de execução fora da política |
| WDAC | 3076 (audit), 3077 (block) | Violações da política de código |
| MSI e Script | 8028/8029/8033 | Bloqueio de instaladores e scripts |

Modo audit-only não é inútil: é a fase de coleta para construir o baseline. O problema é quando ele vira estado permanente.

## Para o red team autorizado

- A primeira pergunta do recon é "audit ou enforce?". `Get-AppLockerPolicy -Effective` responde, e a diferença muda o engajamento inteiro.
- Mapear paths graváveis dentro de paths permitidos é recon de meia hora que rende semanas.
- No relatório, avaliar a política pelo que ela permite, não pelo que ela bloqueia. Uma política com `C:\Windows\*` permitido e subpasta gravável não é whitelisting; é decoração.

## Contrapartida defensiva

1. Começar em audit, coletar baseline real, e ter data para sair do audit. Audit eterno é o fracasso mais comum.
2. Evitar regra de path larga. Quando inevitável, auditar permissão de escrita em cada path permitido.
3. Cobrir script, DLL e driver, não só exe.
4. Refinar regra de publisher: produto e versão, não vendor genérico.
5. Proteger a própria política: só tier 0 altera WDAC/AppLocker, e alteração gera alerta.
6. Combinar com o resto da pilha. Whitelisting não substitui EDR; tira volume do problema.

## Referências

- Microsoft: documentação de WDAC e AppLocker, eventos 8003-8033, 3076/3077
- MITRE ATT&CK: T1218 (LOLBins), T1204 (execução via usuário), T1553 (subvert trust controls)
- Relacionado neste repositório: doc 02 (pilha), doc 04 (matriz de detecção), doc 09 (LOLBins)
