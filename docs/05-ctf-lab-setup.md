# 05 — Lab de CTF autorizado

Como estudar detecção/evasão de forma legal e segura.

## Regras de ouro

1. **Escopo escrito** — CTF com regras publicadas, contrato de pentest, ou lab 100% seu.
2. **Isolamento de rede** — VMs em host-only/internal network; sem ponte para rede corporativa.
3. **Snapshots** — antes de cada experimento; reverta ao final.
4. **Nada de amostras reais de malware fora do lab** — e nunca em máquina de uso pessoal/produção.
5. **Egress control** — se o lab precisa de internet, filtre destinos (proxy/sinkhole).

## Topologia mínima

| VM | Papel | Config |
|---|---|---|
| Windows 10/11 (evaluation) | Alvo | Defender ligado, cloud protection, Tamper Protection; snapshots limpos |
| Windows (segunda) | Atacante/red team | Ferramentas de build e análise; sem dados pessoais |
| Linux (opcional) | Análise | REMnux/FLARE-like: DIE, YARA, strings, sandboxes locais |

## Configuração útil da VM alvo

- **Telemetria visível**: Sysmon com config pública (SwiftOnSecurity/Olaf), PowerShell Script Block Logging, auditoria de processo com cmdline.
- **Defender em modo padrão** — o objetivo do estudo é a detecção real; desligar proteções invalida o aprendizado (exceção: desligar Tamper Protection apenas quando o exercício é sobre T1562.001, e documentar).
- **MDE trial** (opcional): Microsoft disponibiliza avaliação do Defender for Endpoint — excelente para ver a correlação de cadeia.

## CTFs e plataformas legítimas para praticar

| Plataforma | Foco |
|---|---|
| HackTheBox (máquinas Windows) | Cadeias completas com AV presente |
| TryHackMe (rooms de AV evasion, red team) | Trilhas guiadas de evasão conceitual |
| CRTO/CRTP/OSCP labs | Engajamentos simulados com detecção real |
| CyberDefenders/Blue Team Labs | Lado defensivo: analisar o que a evasão deixou |
| Atomic Red Team (em casa) | Executar e detectar técnicas ATT&CK no próprio lab |

## Metodologia de estudo sugerida

1. Escolha uma categoria do doc 03 (ex.: LOLBins).
2. Execute o caso benigno/Atômico no lab e **observe a telemetria** gerada (doc 04).
3. Compare: o que a camada X viu vs. o que a camada Y viu.
4. Documente o sinal residual — esse é o entregável real de um red team maduro.
5. Repita com o chapéu de blue team: escreva a regra de detecção para o que você executou.

## Ética

O objetivo do lab é entender **sistemas de detecção**, não produzir ferramentas de ataque. Publicar PoCs de bypass funcional de AV prejudica defensores reais e pode violar ToS de plataformas e legislação — mantenha o trabalho no nível conceitual/educacional deste repositório.
