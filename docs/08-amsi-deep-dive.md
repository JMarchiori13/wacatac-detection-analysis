# 08 — AMSI em profundidade

> Perspectiva defensiva, com leitura ofensiva. A AMSI (Antimalware Scan Interface) é a API do Windows que deixa aplicações entregarem conteúdo em memória para o antivírus antes de executá-lo. Antes dela, script era terra de ninguém: bastava ofuscar que nenhum scanner de disco via nada. Depois dela, a ofuscação em script praticamente acabou como técnica eficaz.

## Arquitetura

O desenho é simples. De um lado, os hosts que chamam a interface; do outro, os providers que recebem o conteúdo.

| Lado | Quem são | Papel |
|---|---|---|
| Hosts | PowerShell, cscript/wscript (VBScript, JScript), Office (macros VBA), CLR (.NET 4.8+), WMI, UAC em alguns fluxos | Chamam `AmsiScanBuffer` ou `AmsiScanString` antes de executar conteúdo |
| Providers | Microsoft Defender (padrão), antivírus de terceiros registrados | Recebem o buffer e devolvem veredito: limpo, suspeito, bloquear |

O provider roda em processo próprio (no caso do Defender) e o resultado volta ao host, que decide se executa ou interrompe. O registro de providers fica no registro do Windows, o que explica por que mexer nele exige privilégio alto e gera telemetria própria.

## O ponto que mudou o jogo: o buffer chega desofuscado

A AMSI não olha o arquivo no disco. Ela olha o conteúdo no momento em que o host vai executar. E os hosts são generosos: o PowerShell, por exemplo, envia o script em camadas, e cada expansão de string, cada decode, cada etapa de desofuscação vira uma nova chamada de scan.

Na prática, isso significa que o autor do script pode empilhar quantas camadas de encoding quiser. Em alguma camada o conteúdo final precisa aparecer em texto claro para o interpretador executar, e é exatamente essa camada que a AMSI recebe. O trabalho inteiro de ofuscação desmorona na última etapa, que é a única que importa.

Comparando os mundos:

| Vetor | Passa pela AMSI? | Quem vigia |
|---|---|---|
| PowerShell | Sim, em camadas | AMSI + Script Block Logging (4104) |
| VBScript/JScript (cscript) | Sim | AMSI |
| Macros VBA (Office) | Sim, comportamento inclusive | AMSI para Office |
| Assemblies .NET | Sim, desde o 4.8 | AMSI no carregamento |
| Código nativo refletido | Não | ETW TI, comportamental, scanners de memória (doc 07) |
| Binário em disco | Não precisa | Camadas 1 a 3 da pilha (doc 02) |

## A irmã mais quieta: Script Block Logging

A AMSI decide em tempo real. O Script Block Logging (Event ID 4104) registra para a posteridade. Toda execução de script PowerShell vira um evento com o conteúdo completo, também desofuscado, bloqueado ou não.

Essa diferença importa muito. Um script que passa pela AMSI por ser novo demais ainda deixa cópia integral de si no log. Para hunting, o 4104 é frequentemente mais útil que a própria AMSI, porque permite procurar padrões em tudo que já rodou, sem depender do veredito do antivírus.

## O que a AMSI não cobre

Saber onde a interface não chega vale tanto quanto saber onde ela chega.

- Processos nativos que nunca chamam a API. O loader manual do doc 07 vive nesse espaço.
- Conteúdo executado por hosts sem instrumentação, como alguns motores de script de terceiros.
- Fluxos que terminam em chamada de API direta, sem interpretador no meio.
- Corrupção do próprio mecanismo: mexer em AMSI é T1562.001, exige privilégio, e tanto o Tamper Protection quanto o EDR tratam essa alteração como evento de alta severidade. Na prática, atacar a AMSI virou mais barulhento do que atravessá-la.

## Para o red team autorizado

- Se o vetor é script ou .NET, assuma AMSI e 4104 no alvo. O teste deixa de ser "o scanner pegou?" e vira "qual camada deixou registro?".
- Ofuscação de script como estratégia principal acabou. O que resta de útil nela é atrasar análise humana, não enganar o motor.
- Documentar no relatório quando o conteúdo passou pela AMSI sem bloqueio mas ficou no 4104: é uma lacuna de hunting, não de prevenção, e o blue team corrige com regra em cima do log.

## Para o blue team

1. Habilite Script Block Logging e Module Logging e mande o 4104 para o SIEM. Sem isso, a AMSI é a única testemunha e ela só fala quando bloqueia.
2. Monitore os eventos do próprio Defender (1116, 1117) junto com alterações de configuração (5001, 5007). Quem mexe na AMSI ou em exclusões entrega a si mesmo.
3. Trate a lista de providers AMSI como objeto de inventário. Provider novo ou ausente merece investigação.
4. Monte detecções sobre o conteúdo do 4104 e não apenas sobre nomes de arquivo. O conteúdo é o que sobra quando todo o resto foi randomizado.
5. Tamper Protection ativado. Barato, e transforma boa parte do T1562.001 em alarme imediato.

## Referências

- Microsoft: documentação da AMSI, Script Block Logging, eventos do Defender
- MITRE ATT&CK: T1562.001 (Impair Defenses), T1059.001 (PowerShell), T1059.005 (VBScript)
- Relacionado neste repositório: doc 02 (pilha de detecção), doc 07 (o que a AMSI não cobre)
