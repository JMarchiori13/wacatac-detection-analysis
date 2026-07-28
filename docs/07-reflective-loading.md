# 07 — T1620: Reflective Code Loading

> Perspectiva dupla (ofensiva e defensiva). Reflective loading é carregar código direto na memória, sem gravar um executável em disco. Sem arquivo, as três primeiras camadas da pilha de detecção (assinatura, heurística estática, emulação) ficam sem alvo. É a resposta natural do atacante a antivírus que ficou bom em ler disco, e por isso virou o padrão em frameworks de C2 e em CTFs.

O problema é que a defesa também sabe disso. Faz anos que fileless deixou de ser território livre.

## Os dois mundos: .NET e nativo

A técnica muda bastante dependendo da plataforma, e a cobertura da defesa também.

### .NET

O CLR carrega assemblies de memória nativamente, via reflexão. Qualquer aplicação .NET pode fazer isso com uma chamada legítima, sem API suspeita, sem truque de alocação. Em cima do papel, é o paraíso do fileless.

Na prática, desde o .NET Framework 4.8 o CLR chama a AMSI a cada carregamento de assembly. O conteúdo do assembly é escaneado antes de executar, e scripts PowerShell passam pela mesma interface. Ou seja: o mundo .NET inteiro está instrumentado. Ofuscar o assembly ajuda contra o scan, mas o comportamento depois do carregamento continua visível.

### Nativo

No mundo nativo não existe loader para memória. Quem quer executar um PE sem tocar o disco precisa reimplementar o trabalho do loader do Windows: alocar memória, mapear seções, resolver imports, aplicar relocações, ajustar permissões. É muito mais código, e cada etapa deixa marca:

| Etapa do carregamento manual | Marca que fica |
|---|---|
| Alocar memória com permissão de escrita e execução | Regiões RWX ou RW que viram RX depois, padrão raro em software normal |
| Mapear um PE sem usar o loader | Memória executável sem arquivo de imagem associado (backing) |
| Resolver imports em runtime | Sequência de `LoadLibrary`/`GetProcAddress` ou walking de PEB, ambos instrumentáveis |
| Transferir execução | Thread iniciada em região que não pertence a nenhum módulo |

A AMSI clássica não enxerga esse caminho, porque nenhum buffer de script passa por ela. Quem vigia é o ETW Threat Intelligence, o monitoramento comportamental e os scanners de memória.

## O que a defesa vê

| Sinal | Fonte | Comentário |
|---|---|---|
| Assembly carregado de memória | AMSI (.NET) | Buffer completo entregue ao provider antes da execução |
| Script executado | AMSI + Script Block Logging (EID 4104) | O 4104 registra o conteúdo final, ofuscado ou não |
| Região RWX em processo | ETW TI, EDR | Software legítimo quase nunca precisa de RWX |
| Página executável sem módulo | Scanners de memória (PE-sieve, Moneta) | Comparação entre listas de módulos e páginas executáveis |
| Imagem em memória divergente do disco | Scanners de memória | Sobreposição com hollowing (doc 06) |
| Chamadas de API em sequência típica de loader | Comportamental, kernel callbacks | Alocar, escrever, proteger, criar thread, nessa ordem |

## Por que "fileless é indetectável" envelheceu mal

Três motivos, e nenhum é novidade para quem trabalha com EDR.

Primeiro: tirar o arquivo do disco não tira o código da memória, e memória virou superfície de scan de rotina. Ferramentas como PE-sieve nasceram exatamente para isso e hoje rodam agendadas em ambientes maduros.

Segundo: a AMSI cobriu o atalho fácil. O caminho .NET/PowerShell, que era o fileless de baixo custo, agora entrega o conteúdo ao antivírus de bandeja.

Terceiro: o carregador manual em nativo é software complexo fazendo coisas raras. Cada etapa incomum é uma chance de detecção, e a cadeia inteira precisa sair limpa para a técnica funcionar.

## Trade-offs para o red team autorizado

- .NET é barato e discreto em disco, mas passa pela AMSI. O trabalho de evasão migra para o conteúdo do assembly e para o comportamento pós-carga.
- Nativo escapa da AMSI e paga o preço em sinais de memória. Quanto mais completo o loader, mais código próprio existe para ser analisado.
- Refletir dentro de um processo alheio (combinando com T1055, doc 06) mistura os sinais dos dois lados: handle cross-process somado a região executável anômala.
- No relatório, vale registrar qual instrumentação a técnica enfrentou e qual sinal ficou. Sem isso, o blue team não consegue fechar a brecha que você usou.

## Contrapartida defensiva

1. Script Block Logging e AMSI ligados, com os eventos 4104 indo para o SIEM. É a fonte mais barata contra fileless em script.
2. ETW Threat Intelligence consumido pelo EDR. Desligar esse provider é, por si só, um evento que merece alerta.
3. Varredura de memória agendada em servidores críticos, com PE-sieve ou Moneta, procurando RWX e imagens divergentes.
4. Regras de correlação em vez de eventos isolados: alocação remota seguida de thread em região sem módulo vale muito mais que qualquer um dos dois sozinho.
5. Bloqueio de carregamento de assemblies não assinados onde fizer sentido (WDAC), reduzindo a superfície .NET em estações sensíveis.

## Referências

- MITRE ATT&CK: T1620 (Reflective Code Loading), T1055 (Process Injection)
- Microsoft: documentação da AMSI, Script Block Logging, ETW Threat Intelligence
- hasherezade: PE-sieve; Forrest Orr: Moneta (ferramentas públicas de análise de memória)
- Relacionado neste repositório: doc 02 (pilha de detecção), doc 03 (categorias), doc 06 (process injection)
