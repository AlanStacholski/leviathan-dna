# Leviathan DNA
### Motor de Fingerprinting Comportamental para Detecção de Ferramentas Ofensivas

> 🇺🇸 [Read in English](README.md)

> *"Atacantes trocam hashes. Trocam nomes. Recompilam o código. Mas o comportamento operacional continua parecido."*

Leviathan DNA é um motor experimental de **análise comportamental em tempo real** que perfila processos em execução pelos seus padrões operacionais — não por assinaturas, hashes ou nomes de arquivo. Ele detecta ferramentas ofensivas modelando *o que elas fazem*, não *o que elas são*.

Desenvolvido como projeto de aprendizado e portfólio, explorando os conceitos centrais por trás dos sistemas modernos de EDR (Endpoint Detection & Response).

---

## Como Funciona

A maioria dos antivírus pergunta: *"Este arquivo é conhecido como malicioso?"*

O Leviathan DNA pergunta: *"Este processo se comporta como uma ferramenta ofensiva?"*

```
Kernel do Windows
      │
      ▼
   Sysmon (driver ETW)          ← captura criação de processos, rede, acesso ao LSASS
      │
      ▼
   Coletor de Eventos            ← subscrição ETW em tempo real via Win32 API
      │
      ▼
   Tabela de Contexto            ← mantém estado comportamental por PID
      │
      ▼
   Motor de Regras               ← avalia regras comportamentais, acumula score
      │
      ▼
   Classificação                 ← BENIGN / SUSPICIOUS / OFFENSIVE-LIKE / CRITICAL
      │
      ▼
   Dashboard ao Vivo             ← interface terminal em tempo real + histórico de incidentes
```

Um processo chamado `chrome.exe` que abre um handle para `lsass.exe` e spawna comandos PowerShell encodados recebe um score alto de similaridade com Mimikatz — independente do seu nome ou hash.

---

## Capacidades de Detecção

Cada regra mapeia para uma técnica do [MITRE ATT&CK](https://attack.mitre.org/) e inclui explicação contextual de *por que* aquele comportamento é suspeito.

| Regra | MITRE | Peso | O que detecta |
|---|---|---|---|
| `lsass_access` | T1003.001 | +50 | Processo abrindo handle para lsass.exe (credential dumping) |
| `suspicious_parent_spawn` | T1566 | +35 | Shell iniciado por processo pai inesperado |
| `encoded_powershell` | T1059.001 | +30 | PowerShell executando comandos codificados em Base64 |
| `ldap_enumeration` | T1087.002 | +20 | Conexões em portas LDAP (reconhecimento de domínio) |
| `dns_recon` | T1018 | +15 | Queries DNS sequenciais em volume anormal |

### Limiares de Classificação

```
Score  0–29   →  BENIGN          (comportamento normal)
Score 30–59   →  SUSPICIOUS      (comportamento incomum)
Score 60–89   →  OFFENSIVE-LIKE  (padrão ofensivo identificado)
Score 90+     →  CRITICAL        (múltiplos indicadores críticos)
```

---

## Dashboard ao Vivo

O motor executa um dashboard terminal em tempo real que atualiza a cada segundo, exibindo processos ativos com score elevado e um histórico persistente de incidentes com explicações comportamentais completas.

```
┌─ Leviathan DNA — Behavioral Fingerprinting Engine ──────────────────────────┐
│  Eventos capturados: 847    Incidentes detectados: 3    14:55:01            │
├─ ● Processos ativos ────────────────────────────────────────────────────────┤
│  PID    Processo        Pai         Score  Status                           │
│  20928  powershell.exe  cmd.exe     65     OFFENSIVE-LIKE                   │
├─ ⚑ Histórico de incidentes ─────────────────────────────────────────────────┤
│  14:53:01  powershell.exe  Score: 65  OFFENSIVE-LIKE                        │
│                                                                             │
│  ▶ encoded_powershell  +30pts  [T1059.001]                                  │
│    O que está acontecendo:                                                  │
│    PowerShell está executando um comando codificado em Base64,              │
│    ocultando seu conteúdo real de inspeções superficiais de log.            │
│                                                                             │
│    Na prática ofensiva:                                                     │
│    Mimikatz, Empire e Cobalt Strike usam esta técnica para executar         │
│    payloads sem escrever scripts em disco.                                  │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Arquitetura

```
leviathan-dna/
│
├── collector/
│   └── event_listener.py      # Subscrição ETW em tempo real (Win32 API)
│
├── engine/
│   ├── process_context.py     # Modelo de estado comportamental por processo
│   ├── rule_engine.py         # Orquestração de regras e avaliação de score
│   ├── whitelist.py           # Processos e pais confiáveis
│   └── rules/
│       ├── credential_access.py   # Detecção de acesso ao LSASS
│       ├── execution.py           # Regras de shell e encoding
│       └── discovery.py           # Regras de reconhecimento de rede e DNS
│
├── output/
│   ├── alert_handler.py       # Registro de incidentes e log em JSON
│   ├── state_writer.py        # Serialização de estado compartilhado (intervalo de 1s)
│   └── dashboard.py           # Interface terminal Rich (processo separado)
│
└── main.py                    # Ponto de entrada do motor
```

### Decisões de Design

**Scoring por regras antes de ML** — começando deliberadamente com regras comportamentais explícitas em vez de modelos estatísticos. Isso força uma compreensão profunda de cada técnica ofensiva e produz detecções transparentes e explicáveis. ML é o próximo passo natural quando o vocabulário comportamental estiver bem definido.

**Acumulação de contexto por processo** — cada PID mantém seu histórico completo de eventos e um score incremental. As regras reavaliadas a cada novo evento permitem que o score escale conforme os comportamentos se acumulam.

**Sysmon como interface com o kernel** — em vez de escrever um driver de kernel (um esforço de meses), o Sysmon cuida da captura de eventos em baixo nível. O motor foca na lógica de detecção, que é a camada arquiteturalmente interessante.

**Isolamento de processo para o dashboard** — a interface roda como processo separado lendo um arquivo JSON de estado compartilhado, mantendo o pipeline de coleta desbloqueado independente do tempo de renderização.

---

## Como Executar

### Pré-requisitos

- Windows 10/11 (o motor usa ETW e Win32 APIs do Windows)
- Python 3.10+
- [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) instalado com configuração comportamental

### Instalar o Sysmon

Baixe o [Sysmon](https://learn.microsoft.com/sysinternals/downloads/sysmon) e a [configuração SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config), depois execute em um PowerShell elevado:

```powershell
.\Sysmon64.exe -accepteula -i sysmonconfig-export.xml
```

### Instalar dependências

```powershell
pip install pywin32 rich
```

### Executar

```powershell
# Deve ser executado como Administrador
python main.py
```

O motor inicia no terminal atual. O dashboard abre automaticamente em uma segunda janela.

---

## Simulando Detecções

Você pode disparar detecções reais sem nenhuma ferramenta ofensiva usando recursos nativos do Windows:

```powershell
# Dispara: encoded_powershell (+30)
$cmd = "Write-Host 'Leviathan Test'"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -EncodedCommand $encoded

# Dispara: dns_recon (+15) — 15 queries DNS sequenciais
1..15 | ForEach-Object {
    Resolve-DnsName "host$_.teste.local" -ErrorAction SilentlyContinue
}
```

---

## Conceitos por Trás do Projeto

Este projeto é uma implementação prática de conceitos usados por plataformas EDR comerciais:

**Heurísticas comportamentais** — em vez de correspondência de assinaturas, as regras descrevem padrões operacionais. É assim que CrowdStrike Falcon, SentinelOne e Microsoft Defender for Endpoint abordam a detecção em seu núcleo.

**Relações parent-child de processos** — a árvore de processos do Windows codifica intenção. Um documento Word spawnando `cmd.exe` não é o mesmo que um terminal spawnando `cmd.exe`, mesmo que o processo resultante seja idêntico.

**ETW (Event Tracing for Windows)** — o pipeline de telemetria em nível de kernel que alimenta dados para o Sysmon e, por meio dele, para este motor. Compreender ETW é fundamental para engenharia de segurança de endpoint no Windows.

**Mapeamento MITRE ATT&CK** — cada regra está ancorada em uma técnica documentada de agente de ameaça, conectando detecções a comportamentos reais de atacantes.

---

## Roadmap

- [ ] Limpeza de processos encerrados (remover PIDs inativos da tabela ativa)
- [ ] Scoring de similaridade comportamental entre múltiplos processos
- [ ] Persistência de sessão (recarregar histórico de incidentes ao reiniciar)
- [ ] Regras adicionais: CreateRemoteThread, execução via WMI, padrões C2 via pipe
- [ ] Dashboard web (FastAPI + WebSocket)
- [ ] Formato de definição de regras estilo YARA

---

## Autor

**Alan Jones Stacholski Júnior**
Estudante de Engenharia de Software | Pós-graduando em Segurança da Informação (UTFPR)
Curitiba, Brasil

[GitHub](https://github.com/AlanStacholski) · [LinkedIn](https://www.linkedin.com/in/alanjr/) · [stacholski.com.br](https://stacholski.com.br)

---

*"O temor do Senhor é o princípio da sabedoria." — Provérbios 9:10*