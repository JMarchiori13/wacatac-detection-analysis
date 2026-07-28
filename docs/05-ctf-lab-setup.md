# 05 — Lab de CTF autorizado

Como estudar detecção e evasão de forma legal, segura e sem dar trabalho para o seu eu do futuro.

## Regras de ouro

1. Escopo por escrito: regras publicadas do CTF, contrato de pentest, ou um lab que é todo seu.
2. Isolamento de rede. VMs em host-only ou rede interna, sem ponte para a rede corporativa.
3. Snapshot antes de cada experimento, revertido no final.
4. Nenhuma amostra real de malware fora do lab, e nunca em máquina de uso pessoal.
5. Se o lab precisa de internet, controle a saída com proxy ou sinkhole.

## Topologia mínima

| VM | Papel | Configuração |
|---|---|---|
| Windows 10/11 (evaluation) | Alvo | Defender com cloud protection e Tamper Protection, snapshot limpo |
| Windows (segunda) | Atacante | Ferramentas de build e análise, zero dado pessoal |
| Linux (opcional) | Análise | REMnux ou similar: DIE, YARA, strings, sandbox local |

## Configuração da VM alvo

- Sysmon com uma config pública (SwiftOnSecurity ou Olaf), Script Block Logging, auditoria de criação de processo com linha de comando.
- Defender em modo padrão. O objetivo do estudo é a detecção real; desligar proteções invalida o aprendizado. A exceção é quando o exercício é sobre T1562.001, e aí o Tamper Protection sai do caminho de propósito e com registro.
- Se quiser ver correlação de cadeia de verdade, a Microsoft oferece trial do Defender for Endpoint.

## Onde praticar legitimamente

| Plataforma | Foco |
|---|---|
| HackTheBox | Cadeias completas em máquinas Windows com AV presente |
| TryHackMe | Rooms guiadas de evasão e red team |
| Labs de CRTO, CRTP, OSCP | Engajamentos simulados com detecção real |
| CyberDefenders e Blue Team Labs | O outro lado: analisar o que a evasão deixou |
| Atomic Red Team | Executar técnicas ATT&CK no próprio lab e observar a telemetria |

## Metodologia sugerida

1. Escolha uma categoria do doc 03. LOLBins é um bom começo.
2. Execute o caso atômico no lab e observe a telemetria que nasce (doc 04).
3. Compare o que cada camada viu. O que a assinatura perdeu, a AMSI pegou? O que a AMSI perdeu, o comportamental viu?
4. Documente o sinal residual. Esse é o entregável de um red team maduro.
5. Troque de chapéu: escreva a regra de detecção para o que você acabou de executar.

## Ética

O objetivo do lab é entender sistemas de detecção, não produzir ferramenta de ataque. Publicar bypass funcional de AV prejudica defensores de verdade e pode violar termos de plataforma e legislação. Mantenha o trabalho no nível conceitual deste repositório.
