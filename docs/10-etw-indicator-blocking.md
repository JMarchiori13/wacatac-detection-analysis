# 10 — T1562.006: ETW e Indicator Blocking

> Perspectiva dupla. A ETW (Event Tracing for Windows) é o sistema nervoso da telemetria moderna: Sysmon, EDR, AMSI avançada e boa parte da visibilidade de um SOC bebem dela. Atacar a ETW é atacar os olhos da defesa, e é por isso que T1562.006 ficou tão estudado dos dois lados.

## Como a ETW funciona

Três papéis, e entender os três é entender onde dá para interferir:

| Papel | Quem é | O que faz |
|---|---|---|
| Provider | Kernel, .NET, PowerShell, AMSI, Threat Intelligence, DNS, LDAP | Gera eventos sobre o que acontece |
| Session/Controller | Logman, o próprio sistema, o agente do EDR | Liga e desliga providers, define destino |
| Consumer | Sysmon, SIEM local, agente de EDR | Lê os eventos e reage |

O detalhe arquitetural que importa: boa parte da escrita de eventos de user-mode passa por funções como `EtwEventWrite`, que vivem na `ntdll.dll` carregada em cada processo. Cada processo tem a própria cópia.

## Categorias conceituais de interferência

### Cegar o próprio processo

A categoria mais conhecida: alterar, na cópia local do processo, a função que escreve eventos ETW, fazendo com que aquele processo pare de relatar. O efeito é local por desenho: os outros processos continuam visíveis. E o próprio fato de um processo parar de emitir eventos que ele deveria emitir virou, com o tempo, um sinal de detecção por ausência.

### Desligar ou remover providers

Em vez de mexer no processo, mexer na sessão: desabilitar um provider específico (como o de Threat Intelligence) ou a sessão de log inteira. Exige privilégio administrativo e gera evento próprio de alteração de configuração. É a versão barulhenta da ideia anterior, com efeito mais amplo.

### Apagar o que já foi escrito

Primo próximo da T1070 (Indicator Removal): limpar logs depois do fato. A defesa madura responde com encaminhamento de eventos em tempo real para fora da máquina, porque log que já saiu do host não se apaga no host.

### Saturar e confundir

Gerar volume enorme de eventos benignos para enterrar o malicioso, ou forçar queda de eventos por limite de buffer. Menos elegante, mas barato e difícil de distinguir de comportamento de sistema sob carga.

## Por que a defesa aprendeu a lidar com isso

Cada categoria tem uma característica em comum: interferir na telemetria é, em si, telemetria. A tabela resume:

| Interferência | Sinal que ela própria gera |
|---|---|
| Processo que para de emitir eventos esperados | Ausência anômala, detectável por baseline de emissão |
| Provider ou sessão desabilitada | Evento de mudança de configuração, alerta imediato |
| Log limpo | Evento 1102 no Security, um dos mais monitorados que existem |
| Saturação | Pico de volume fora do padrão, queda de eventos registrada |
| EDR desligado ou agente morto | Heartbeat perdido, o alerta mais básico de qualquer SOC |

A conclusão prática é parecida com a da AMSI (doc 08): atacar o mecanismo de detecção virou, na maioria dos ambientes, mais visível do que atravessá-lo com cuidado.

## Kernel vs. user-mode

Providers de kernel (criação de processo, imagem carregada, rede) não são afetados por truques em user-mode. Cegar a cópia local de `EtwEventWrite` esconde eventos de aplicação, mas a criação do processo, os drivers carregados e as conexões continuam sendo relatados pelo kernel. Por isso EDRs sérios misturam telemetria de kernel com a de user-mode: derrubar uma camada não derruba a outra.

## Para o red team autorizado

- Antes de pensar em cegar telemetria, mapeie quais fontes o alvo realmente consome. Sysmon sem encaminhamento remoto é muito diferente de MDE com heartbeat.
- Interferência local (processo único) deixa o resto da máquina visível. Avalie se o ganho cobre o risco do sinal de ausência.
- No relatório, documente qual fonte de telemetria o ambiente não tinha. Uma cadeia que nunca precisou cegar nada porque ninguém estava olhando é a constatação mais útil que você pode entregar.

## Contrapartida defensiva

1. Encaminhamento de eventos em tempo real (WEF, agente de SIEM). Log fora do host não é apagado pelo host.
2. Alerta no evento 1102 e em mudanças de configuração de log e providers. São poucos eventos, alto valor.
3. Heartbeat de agente com alerta de perda. O silêncio do sensor é, por definição, um evento.
4. Telemetria de kernel além da de user-mode, para que uma camada cubra a cegueira da outra.
5. Baseline de emissão de eventos por processo crítico. A ausência também é dado.

## Referências

- MITRE ATT&CK: T1562.006 (Indicator Blocking), T1562.001 (Impair Defenses), T1070 (Indicator Removal)
- Microsoft: documentação de ETW, providers de kernel e Threat Intelligence
- Relacionado neste repositório: doc 02 (pilha de detecção), doc 04 (matriz de detecção), doc 08 (AMSI)
