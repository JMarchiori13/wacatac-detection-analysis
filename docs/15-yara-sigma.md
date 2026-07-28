# 15 — YARA e Sigma: Regras Prontas deste Repositório

> Perspectiva defensiva, em código. Os docs anteriores explicam o que procurar. Este entrega as regras. Elas vivem na pasta `rules/` e seguem a mesma linha editorial: detecção, nunca ofensa.

## Estrutura

| Arquivo | Tipo | Cobre |
|---|---|---|
| `rules/yara/packer_heuristics.yar` | YARA | Estrutura de PE típica de packer (doc 03) |
| `rules/yara/discord_token_regex.yar` | YARA | Formato de token do Discord |
| `rules/yara/exfil_and_phishing.yar` | YARA | Staging de exfiltração e strings de phishing |
| `rules/sigma/lolbin_certutil_download.yml` | Sigma | `certutil` com URL (doc 09) |
| `rules/sigma/lolbin_rundll32_user_path.yml` | Sigma | `rundll32` com DLL em pasta de usuário (doc 09) |
| `rules/sigma/remote_thread_injection.yml` | Sigma | CreateRemoteThread (doc 06) |
| `rules/sigma/sam_hive_reg_save.yml` | Sigma | Exportação de hives de credencial |
| `rules/sigma/lsass_access_dump.yml` | Sigma | Acesso amplo ao lsass (EID 10) |
| `rules/sigma/wmi_event_subscription.yml` | Sigma | Persistência via WMI (doc 12) |
| `rules/sigma/logon_type_9_newcredentials.yml` | Sigma | Logon tipo 9, Pass-the-Hash (doc 13) |

## Como usar

YARA e Sigma são formatos de regra, não ferramentas. YARA roda contra arquivos e memória com o binário `yara`; Sigma é um formato intermediário que se converte para a query do seu SIEM com `sigmac` ou pySigma. As regras aqui são ponto de partida: ajuste aos nomes e índices do seu ambiente antes de produção.

## Notas de calibração

- `packer_heuristics` gera falso positivo em instaladores legítimos empacotados (NSIS, jogos). Use para triagem, não para bloqueio automático.
- `discord_token_regex` em varredura de memória é cirúrgica; em disco, produz ruído de cache de navegador.
- `certutil` é usado por scripts legítimos de PKI em algumas redes. Vale filtro por host.
- `lsass_access_dump` precisa de ajuste de filtro para o AV/EDR do seu ambiente; cada fornecedor acessa o lsass do próprio jeito.
- `logon_type_9` filtra `runas.exe` padrão, mas administradores que usam `runas /netonly` vão aparecer. Em ambiente bem administrado, isso é raro o suficiente para valer o alerta.

## Contribuir

Regra nova segue o mesmo caminho de qualquer contribuição (CONTRIBUTING.md): abra issue descrevendo o que a regra detecta, a fonte e a taxa de falso positivo esperada. Regra sem contexto de FP não entra.
