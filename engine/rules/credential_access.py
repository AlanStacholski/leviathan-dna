from engine.process_context import ProcessContext


def rule_lsass_access(ctx: ProcessContext):
    for event in ctx.events:
        if event["event_id"] == 10:
            target = event["data"].get("TargetImage", "").lower()
            if "lsass.exe" in target:
                return {
                    "rule": "lsass_access",
                    "weight": 50,
                    "reason": f"Handle aberto para lsass.exe",
                    "behavior": (
                        "O processo abriu um handle direto para lsass.exe, o processo "
                        "responsável por armazenar credenciais autenticadas na memória. "
                        "Isso permite leitura do conteúdo da memória desse processo."
                    ),
                    "offensive_context": (
                        "Mimikatz usa exatamente este acesso para extrair hashes NTLM, "
                        "tickets Kerberos e senhas em texto claro da memória do sistema. "
                        "É o comportamento mais característico de credential dumping — "
                        "T1003.001 no MITRE ATT&CK. EDRs modernos bloqueiam este acesso "
                        "por padrão em ambientes protegidos."
                    ),
                    "mitre": "T1003.001"
                }
    return None