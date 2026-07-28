# 15 — YARA e Sigma: Regras Prontas deste Repositório

> Perspectiva defensiva, em código. Os docs anteriores explicam o que procurar. Este entrega as regras. Elas vivem na pasta `rules/` e seguem a mesma linha editorial: detecção, nunca ofensa.

## Estrutura

| Arquivo | Tipo | Cobre |
|---|---|---|
| `rules/yara/packer_heuristics.yar` | YARA | Estrutura de PE típica de packer (doc 03) |
| `rules/yara/discord_token_regex.yar` | YARA | Formato de token do Discord em memória/arquivos |
| `rules/sigma/lolbin_certutil_download.yml` | Sigma | `certutil` com URL (doc 09) |
| `rules/sigma/remote_thread_injection.yml` | Sigma | CreateRemoteThread (doc 06) |
| `rules/sigma/sam_hive_reg_save.yml` | Sigma | Exportação de hives de credencial |

## Como usar

YARA e Sigma são formatos de regra, não ferramentas. YARA roda contra arquivos e memória com o binário `yara`; Sigma é um formato intermediário que se converte para a query do seu SIEM com `sigmac` ou pySigma. As regras aqui são ponto de partida: ajuste aos nomes e índices do seu ambiente antes de produção.

## Notas de calibração

- `packer_heuristics` gera falso positivo em instaladores legítimos empacotados (NSIS, jogos). Use para triagem, não para bloqueio automático.
- `discord_token_regex` em varredura de memória é cirúrgica; em disco, produz ruído de cache de navegador.
- As três Sigma têm precisão alta em ambiente corporativo típico, mas `certutil` é usado por scripts legítimos de PKI em algumas redes. Vale o filtro por host.

## Contribuir

Regra nova segue o mesmo caminho de qualquer contribuição (CONTRIBUTING.md): abra issue descrevendo o que a regra detecta, a fonte e a taxa de falso positivo esperada. Regra sem contexto de FP não entra.
