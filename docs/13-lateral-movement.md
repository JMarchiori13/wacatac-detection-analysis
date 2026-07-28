# 13 — T1021: Movimento Lateral em Profundidade

> Perspectiva dupla. O doc 07 tratou da persistência, de ficar. Este trata de andar: usar a credencial coletada para alcançar o próximo host. O Windows é generoso em protocolos legítimos de administração remota, e cada um deles é também um veículo de movimento lateral.

## Os protocolos, um por um

| Protocolo | Uso legítimo | Abuso conceitual | Telemetria |
|---|---|---|---|
| SMB/Admin$ (T1021.002) | Compartilhamento administrativo, psexec legítimo | Copiar binário para `\\host\ADMIN$` e criar serviço remoto | EID 5140/5145 (share acessado), 7045 no alvo (serviço novo) |
| WinRM (T1021.006) | Administração remota padrão moderna | `Enter-PSSession`, `Invoke-Command` com credencial roubada | EID 91/168 no WinRM, processo `wsmprovhost` no alvo |
| RDP (T1021.001) | Acesso interativo remoto | Logon com credencial válida; sessão gráfica | EID 4624 tipo 10, 4778/4779, RDP bmp cache |
| WMI (T1047) | Gerenciamento remoto | `wmic /node: process call create` | Processo filho de `WmiPrvSE.exe` no alvo |
| DCOM (T1021.003) | Automação COM remota | Instanciação de objetos COM remotos (MMC, ShellWindows) | Rede para porta 135 + processo incomum no alvo |
| SSH (T1021.004) | Administração de Linux e, cada vez mais, Windows | Chave ou senha coletada (doc 03 do repo irmão) | Log do sshd, sessões em horário incomum |

## O padrão que a defesa precisa enxergar

Todo movimento lateral deixa a mesma assinatura de três partes: autenticação remota bem-sucedida, ação administrativa no alvo, e tráfego entre dois hosts que normalmente não conversam. Nenhuma das três é anômala sozinha numa rede corporativa. A correlação das três é.

É por isso que o EID 4624 com tipo de logon certo é tão valioso:

| Tipo de logon | Significa | Suspeito quando |
|---|---|---|
| 3 (rede) | SMB, WMI, WinRM, IIS | Conta de usuário comum autenticando em servidor |
| 10 (interativo remoto) | RDP | Usuário fazendo RDP para máquina que não administra |
| 9 (NewCredentials) | `runas /netonly`, Pass-the-Hash clássico | Sempre raro; merece alerta |

## O que distingue o lateral maduro do barulhento

O movimento lateral amador usa o protocolo errado para o ambiente: psexec numa rede que administra por WinRM, RDP fora de horário, conta local onde tudo é domínio. O maduro imita o fluxo administrativo real: mesmo protocolo, mesma faixa de horário, mesma conta de automação. A defesa que depende de assinatura simples pega o primeiro e não vê o segundo. A que tem baseline de comportamento administrativo pega os dois.

## Para o red team autorizado

- Mapeie como a equipe de TI administra o ambiente antes de se mover. O melhor movimento lateral é indistinguível do trabalho dela.
- Conta local em rede de domínio, e domínio onde só conta local é usada, são os dois erros mais comuns e mais detectáveis.
- No relatório, liste quais protocolos administrativos o cliente não monitora. Quase sempre sobra um.

## Contrapartida defensiva

1. Baseline de administração: quais contas, de quais hosts, por quais protocolos, em que horários.
2. Alerta em 4624 tipo 3 e 10 fora do baseline, e em 4624 tipo 9 sempre.
3. Admin$ fechado para contas que não são de administração; WinRM restrito por GPO a sub-redes de gestão.
4. Tiering: conta de admin de servidor não loga em estação, conta de estação não loga em servidor.
5. Honey credentials: conta canário cujo uso em qualquer protocolo dispara alerta de máxima prioridade.

## Referências

- MITRE ATT&CK: T1021 e sub-técnicas, T1047, T1550 (uso de credencial)
- Microsoft: documentação de WinRM, eventos de logon, AdminSDHolder
- Relacionado neste repositório: doc 06 (injeção), doc 12 (persistência), doc 07 do repo irmão (coleta para lateral)
