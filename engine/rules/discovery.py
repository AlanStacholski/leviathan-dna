from engine.process_context import ProcessContext


def rule_ldap_enumeration(ctx: ProcessContext):
    ldap_ports = {"389", "636", "3268", "3269"}
    for event in ctx.events:
        if event["event_id"] == 3:
            dest_port = event["data"].get("DestinationPort", "")
            if dest_port in ldap_ports:
                return {
                    "rule": "ldap_enumeration",
                    "weight": 20,
                    "reason": f"Conexão na porta LDAP {dest_port}",
                    "behavior": (
                        "O processo estabeleceu conexão em uma porta LDAP. "
                        "LDAP é o protocolo usado para consultar o Active Directory, "
                        "incluindo usuários, grupos, computadores e políticas do domínio."
                    ),
                    "offensive_context": (
                        "SharpHound e BloodHound usam LDAP para mapear todo o Active "
                        "Directory e identificar caminhos de escalação de privilégio. "
                        "Uma conexão LDAP isolada pode ser legítima, mas combinada com "
                        "outros comportamentos indica reconhecimento de domínio — T1087.002."
                    ),
                    "mitre": "T1087.002"
                }
    return None


def rule_dns_recon(ctx: ProcessContext):
    dns_events = [e for e in ctx.events if e["event_id"] == 22]
    if len(dns_events) >= 10:
        return {
            "rule": "dns_recon",
            "weight": 15,
            "reason": f"{len(dns_events)} queries DNS em sequência",
            "behavior": (
                f"O processo realizou {len(dns_events)} queries DNS em sequência. "
                "Volume anormal de resolução de nomes pode indicar varredura "
                "de hosts ou tentativa de descoberta de infraestrutura."
            ),
            "offensive_context": (
                "Ferramentas de reconhecimento como nmap, masscan e scripts customizados "
                "resolvem grandes listas de hostnames para mapear a rede antes de um ataque. "
                "T1018 — Remote System Discovery no MITRE ATT&CK."
            ),
            "mitre": "T1018"
        }
    return None