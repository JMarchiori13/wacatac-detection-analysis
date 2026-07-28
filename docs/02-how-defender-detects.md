# 02 — Como o Microsoft Defender detecta

Antes de falar em evasão, ou em defesa, vale entender o que está do outro lado. O Defender não é um scanner de assinaturas. É uma pilha de camadas que atuam em momentos diferentes, e cada uma tem um ponto cego distinto.

## As camadas

### 1. Assinaturas estáticas

Padrões de bytes, hashes, estruturas de PE e sequências de código, atualizados várias vezes ao dia pelo Security Intelligence. Rápidas e precisas contra o que já é conhecido. O ponto fraco é óbvio: qualquer mutação que quebre o padrão aposenta a assinatura.

### 2. Heurística estática

Regras sobre características do arquivo, em vez de conteúdo exato. Entropia alta indica packer ou criptografia. Seções de PE anômalas, poucos imports combinados com `LoadLibrary` e `GetProcAddress`, falta de assinatura digital. A maioria dos falsos positivos em packers e cracks nasce aqui.

### 3. Emulação

Antes de liberar um executável, o Defender roda o começo dele em um emulador de CPU interno. É assim que ele desempacota UPX e packers simples sem ajuda, e que enxerga strings que só existem decriptadas em runtime. O limite também é claro: a emulação tem orçamento de tempo. Sleeps, loops longos e checagens de ambiente servem para esgotar esse orçamento.

### 4. AMSI

A interface que escaneia conteúdo em memória: PowerShell, VBScript, JScript, macros de Office, assemblies .NET, WMI. O host entrega o buffer ao antivírus antes de executar, o que mata a ofuscação de script como estratégia. O doc 08 é dedicado a ela.

### 5. Comportamental

Sequências de chamadas de API, processos filhos suspeitos, injeção, escrita em locais protegidos, persistência em Run keys, serviços e tasks. Funciona contra binários que passaram limpos por todas as camadas anteriores.

### 6. Nuvem e machine learning

Arquivos desconhecidos são consultados contra modelos de ML da Microsoft. Daí saem os vereditos com `!ml`, incluindo o Wacatac. O Block at First Sight segura arquivos nunca vistos até a nuvem decidir. Depende de conectividade e telemetria habilitadas.

### 7. SmartScreen

Reputação baseada em prevalência e assinatura. Arquivo novo, raro e sem assinatura ganha aviso ou bloqueio no download.

### 8. ETW e EDR

Event Tracing for Windows alimenta o Defender e os EDRs. O Defender for Endpoint correlaciona processo, memória, rede e registro depois da execução. É a camada que costuma pegar red teams: o binário passa no scan, mas a cadeia de comportamento o entrega.

## Mapa resumido

| Camada | Quando atua | O que pega |
|---|---|---|
| Assinatura | Scan de disco | Malware conhecido |
| Heurística | Scan de disco | Packers, estruturas suspeitas |
| Emulação | Pré-execução | Unpacking, strings dinâmicas |
| AMSI | Carga em memória | Scripts, .NET, fileless |
| Comportamental | Execução | Sequências maliciosas |
| Cloud ML | Sob demanda | Desconhecidos (`!ml`) |
| SmartScreen | Download | Baixa reputação |
| EDR/ETW | Pós-execução | Cadeias de ataque |

## Implicação prática

Passar por uma camada não significa nada sozinho. Cada vetor de ataque atravessa um subconjunto da pilha, e a evasão só funciona se atravessar todas as camadas desse subconjunto. Os docs 03 e 04 detalham esse jogo dos dois lados.
