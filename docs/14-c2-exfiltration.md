# 14 — C2 e Exfiltração (T1071, T1041 e vizinhas)

> Perspectiva dupla. Tudo o que veio antes neste repositório gera valor dentro do host. Este documento cobre a saída: como o resultado sai da rede e como o atacante conversa com o implante enquanto isso. C2 e exfiltração são as fases em que o atacante não tem como evitar a rede, e a rede é o território mais antigo da defesa.

## O problema do atacante, honestamente

Toda técnica anterior pode ser fileless, LOLBin, assinada, indetectável. Na hora de falar com o mundo exterior, não existe fileless: um pacote precisa sair. E pacote que sai passa por proxy, firewall, DNS, TLS inspection e, em ambiente maduro, por análise de comportamento de rede acumulada por semanas. A fase de C2 é onde engajamentos bem executados em endpoint morrem.

## Canais de C2 (conceitual)

| Canal | Por que atrai | Por que entrega |
|---|---|---|
| HTTPS para servidor próprio (T1071.001) | Tráfego web é permitido em toda rede | Destino raro, padrão de beacon, JA3/JA3S, certificado novo |
| DNS (T1071.004) | DNS quase nunca é bloqueado | Volume de queries anômalo, subdomínios longos e aleatórios, domínio novo |
| Serviços legítimos (T1102): GitHub, Slack, Google Drive, Telegram | Reputação do destino é impecável | Conta de serviço desconhecida, API fora do uso humano, volume fora de hora |
| Protocolos de e-mail (T1071.003) | SMTP/IMAP saem em muitas redes | Anexo padrão, destinatário fixo, horário de beacon |
| ICMP/outros exóticos | Raramente inspecionados | Raramente permitidos; quando passam, o volume denuncia |

## O beacon e seu calcanhar

Implante que conversa em intervalo regular (beacon) gera o padrão mais caçado da defesa de rede: conexões periódicas de tamanho parecido para o mesmo destino. A resposta ofensiva é o jitter, intervalo variável que quebra a periodicidade. A resposta da defesa ao jitter é análise estatística: mesmo com intervalo variável, a média, o desvio e a regularidade de tamanho continuam lá. É uma corrida de estatística, e a defesa tem mais dados.

## Exfiltração

| Técnica | Conceito | Sinal |
|---|---|---|
| Sobre o próprio C2 (T1041) | Aproveita o canal aberto | Mesmo monitoramento do C2, com volume de saída assimétrico |
| Cloud storage (T1567.002) | Upload para Drive, Dropbox, Mega | Destino de storage fora do padrão do usuário, upload grande |
| DNS tunneling | Dados em queries | Mesma análise do C2 por DNS, com volume maior |
| Compactação e staging (T1560) | Dados reunidos e zipados antes de sair | Arquivo compactado grande em pasta temporária (Sysmon EID 11) |
| Protocolo alternativo (T1048): FTP, SFTP, porta alta | Sai por onde o proxy não olha | Tráfego de saída que não passa pelo proxy corporativo |

## O ponto que a defesa precisa segurar

Exfiltração relevante tem tamanho. Um beacon são bytes; um roubo de dados são megabytes ou gigabytes de saída. A métrica mais simples e mais negligenciada da defesa é a razão upload/download por host. Estação que historicamente baixa e de repente sobe, sobe muito, é anomalia estatística básica, e pega exfiltração mesmo quando o canal é sofisticado.

## Para o red team autorizado

- Teste primeiro se a saída existe. Metade dos ambientes bloqueia tudo que não é proxy, e a outra metade não sabe que não bloqueia.
- C2 por serviço legítimo (T1102) é o cenário que mais ensina o cliente, porque a defesa dele quase nunca inventoria quais contas de GitHub ou Slack a rede acessa.
- No relatório, separe o que a rede viu do que o endpoint viu. A interseção cega é o mapa de melhoria do cliente.

## Contrapartida defensiva

1. Egress control: tudo sai pelo proxy, e o que não passa pelo proxy não sai. Sem exceção para "só esse servidor".
2. DNS por resolver interno, com análise de volume, entropia de subdomínio e idade de domínio.
3. JA3/JA3S ou fingerprinting de TLS no proxy, quando há inspection.
4. Razão upload/download por host, com alerta em desvio do histórico.
5. Inventário de serviços legítimos usados como canal: quais contas de storage e colaboração a rede acessa, e de onde.

## Referências

- MITRE ATT&CK: T1071, T1041, T1048, T1102, T1567, T1560
- SigmaHQ e pesquisa pública de detecção de beacon e DNS tunneling
- Relacionado neste repositório: doc 12 (persistência), doc 13 (lateral), doc 10 (ETW e a cegueira de rede)
