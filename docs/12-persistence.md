# 12 — Persistência no Windows (T1543, T1547 e vizinhas)

> Perspectiva dupla. Conseguir execução uma vez é metade do trabalho. A outra metade é continuar executando depois de reboot, logoff e patch. Persistência é a resposta do atacante, e o Windows oferece dezenas de ganchos legítimos para isso. A defesa, por sua vez, sabe onde quase todos eles moram.

## Por que persistência é visível

Persistência tem um preço estrutural: ela precisa ser durável, então precisa ser escrita em algum lugar que sobreviva a reboot. Registro, disco, banco de tarefas, configuração de serviço. Tudo isso é auditável, e ferramentas como o Autoruns da Sysinternals inventariam a maioria desses pontos em segundos. A persistência troca furtividade imediata por sobrevivência, e essa troca é o que a defesa explora.

## Os clássicos

| Mecanismo | Local | Como é abusado | Detecção |
|---|---|---|---|
| Run keys (T1547.001) | `HKLM/HKCU\Software\Microsoft\Windows\CurrentVersion\Run` e `RunOnce` | Executável ou comando a cada logon | Sysmon EID 13, Autoruns, baseline de Run keys |
| Serviços (T1543.003) | `HKLM\SYSTEM\CurrentControlSet\Services` | Serviço novo ou binário de serviço trocado | EID 7045 (serviço criado), Sysmon EID 13, revisão de ImagePath |
| Tarefas agendadas (T1053.005) | `C:\Windows\System32\Tasks` + registro | Tarefa com trigger de logon/horário, nome que imita sistema | EID 4698, Sysmon EID 11 em Tasks, comparação com baseline |
| Startup folder (T1547.001) | `%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup` | Atalho ou script na pasta | Sysmon EID 11, inventário da pasta |
| Winlogon (T1547.004) | `HKLM\...\Winlogon` (Shell, Userinit) | Appending de binário em valores de inicialização | Sysmon EID 13, validação dos valores contra o padrão |
| Image File Execution Options (T1546.012) | `HKLM\...\Image File Execution Options\<exe>` | Debugger apontando para payload: abrir notepad abre o atacante | Sysmon EID 13, auditoria de IFEO |
| WMI event subscription (T1546.003) | Repositório WMI (`__EventFilter`, `__EventConsumer`) | Evento WMI dispara comando; vive fora do registro comum | Sysmon EID 19/20/21, revisão do repositório |

## Os mais discretos

| Mecanismo | Por que é mais sutil |
|---|---|
| Shim database (T1546.011) | Correção de compatibilidade falsa injeta lógica em programa legítimo |
| COM hijack (T1546.015) | CLSID redirecionado para DLL do atacante; execução via componente confiável |
| DLL search order (T1574.001) | DLL plantada em pasta que o programa consulta antes da system32 |
| Screensaver (T1546.002) | `SCRNSAVE.EXE` no registro apontando para payload |
| Time providers (T1547.003) | DLL de provedor de tempo carregada pelo W32Time |
| Print monitors (T1547.012) | Driver de monitor de impressão carregado pelo spooler, como SYSTEM |

## Persistência vs. furtividade, o trade-off real

Cada mecanismo escolhe um ponto na curva. Run key é trivial de criar e trivial de achar. WMI subscription e shim são mais raros, mas exigem mais privilégio e deixam marcas menos familiares para o analista, o que corta nos dois sentidos: a defesa olha menos, mas a operação erra mais.

O que os engajamentos mostram com consistência: persistência barata em ambiente sem inventário dura meses; persistência sofisticada em ambiente com baseline de Autoruns cai em dias. O fator decisivo não é a técnica. É a existência do baseline.

## Para o red team autorizado

- Persistência é a fase com mais chance de detecção do engajamento. Vale documentar no relatório quanto tempo cada implante sobreviveu e o que o entregou.
- Dois mecanismos de perfis diferentes (um comum, um raro) ensinam mais ao cliente que cinco do mesmo tipo.
- Testar o processo de limpeza do cliente faz parte do favor: remover toda a persistência no final e confirmar com o blue team que nada ficou.

## Contrapartida defensiva

1. Autoruns agendado com saída para o SIEM, comparado ao baseline. É o detector de persistência mais barato que existe.
2. Sysmon EID 13 nos hives de persistência e EID 11 nas pastas de startup e Tasks.
3. Alerta em EID 7045 (serviço novo) e 4698 (tarefa nova), dois eventos de baixo volume e alto valor.
4. Inventário de IFEO, WMI subscriptions e shims, os pontos que o Autoruns cobre menos diretamente.
5. Resposta a incidente com revisão de persistência antes de reimagem: entender o que persistiu ensina como o atacante pensa.

## Referências

- MITRE ATT&CK: T1543, T1547, T1546, T1574, T1053.005
- Sysinternals Autoruns e documentação do Sysmon
- Relacionado neste repositório: doc 04 (matriz de detecção), doc 10 (ETW), doc 11 (WDAC como prevenção)
