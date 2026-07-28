# 02 — Como o Microsoft Defender detecta

Entender a pilha de detecção é pré-requisito para qualquer discussão séria sobre evasão (ou defesa). O Defender não é um scanner de assinaturas — é uma pilha em camadas.

## Camadas da pilha

### 1. Assinaturas estáticas (on-disk)

- Padrões de bytes, hashes, estruturas PE, sequências de código.
- Atualizadas várias vezes ao dia via Security Intelligence Updates.
- **Ponto fraco**: qualquer mutação que quebre o padrão invalida a assinatura.

### 2. Heurística estática

- Regras sobre características do arquivo: entropia alta (packed/encrypted), seções PE anômalas, imports suspeitos (poucos imports + `LoadLibrary`/`GetProcAddress`), ausência de assinatura digital, recursos embutidos incomuns.
- É aqui que a maioria dos falsos positivos de packers/cracks nasce.

### 3. Emulação

- O Defender executa o binário em um **emulador de CPU interno** antes de liberar.
- Desempacota UPX e packers simples automaticamente, observa strings decriptadas em runtime e comportamento inicial.
- Limitação: emulação é parcial e com tempo limitado — loops longos, sleeps e checagens de ambiente esgotam o emulador.

### 4. AMSI (Antimalware Scan Interface)

- Interface para conteúdo **em memória**: scripts PowerShell, VBScript, JScript, .NET (assembly load), WMI.
- Ferramentas como `powershell.exe`, `cscript`, Office macros e CLR chamam `AmsiScanBuffer` antes de executar conteúdo.
- É a camada que pega payloads fileless e ofuscação de script em runtime.

### 5. Monitoramento comportamental (runtime)

- Sequências de chamadas de API, criação de processos filhos suspeitos, injeção, escrita em pastas protegidas, persistência (Run keys, serviços, tasks).
- Funciona mesmo para binários que passaram nas camadas 1–4.

### 6. Cloud-delivered protection (MAPS) + ML

- Metadados e amostras são consultados/enviados à nuvem Microsoft.
- Modelos de ML classificam arquivos desconhecidos — origem das detecções `!ml` (incluindo Wacatac.B!ml).
- **Block at First Sight (BAFS)**: arquivos nunca vistos podem ser bloqueados até a nuvem decidir.
- Dependência: exige conectividade e telemetria habilitada.

### 7. SmartScreen / reputação

- Baseado em prevalência e assinatura: arquivos raros, novos ou não assinados ganham aviso/bloqueio ao baixar (Mark-of-the-Web).

### 8. ETW e sensores auxiliares

- Event Tracing for Windows alimenta o Defender e EDRs (AMSI providers, Threat Intelligence ETW).
- Microsoft Defender for Endpoint (EDR) correla processo/rede/registro — camada pós-execução.

## Mapa resumido

| Camada | Quando atua | O que pega |
|---|---|---|
| Assinatura | Scan de disco | Malware conhecido |
| Heurística | Scan de disco | Packers, estruturas suspeitas |
| Emulação | Pré-execução | Unpacking, strings dinâmicas |
| AMSI | Carregamento em memória | Scripts, .NET, fileless |
| Comportamental | Execução | Sequências maliciosas |
| Cloud ML | Sob demanda | Desconhecidos (`!ml`) |
| SmartScreen | Download/execução | Baixa reputação |
| EDR/ETW | Pós-execução | Cadeias de ataque |

## Implicação chave

Evasão confiável exige passar por **todas** as camadas relevantes ao vetor — não só pela assinatura. E é por isso que a detecção comportamental + EDR é o que normalmente captura red teams: o binário passa no scan, mas a **cadeia de comportamento** o entrega. Ver docs 03 e 04.
