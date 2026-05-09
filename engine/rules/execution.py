from engine.process_context import ProcessContext
from engine.whitelist import is_trusted_parent


def rule_encoded_powershell(ctx: ProcessContext):
    cmd = ctx.command_line.lower()
    if "-encodedcommand" in cmd or " -enc " in cmd:
        return {
            "rule": "encoded_powershell",
            "weight": 30,
            "reason": f"Parâmetro de encoding detectado na linha de comando",
            "behavior": (
                "PowerShell está executando um comando codificado em Base64. "
                "Isso oculta o conteúdo real do comando de sistemas de log superficiais "
                "e de analistas que monitoram apenas o nome do processo."
            ),
            "offensive_context": (
                "Ferramentas como Mimikatz, Empire, Cobalt Strike e scripts de "
                "phishing usam esta técnica para executar payloads completos sem "
                "escrever arquivos em disco. É uma das técnicas mais comuns em "
                "ataques reais — T1059.001 no MITRE ATT&CK."
            ),
            "mitre": "T1059.001"
        }
    return None


def rule_suspicious_parent(ctx: ProcessContext):
    shell_targets = {"cmd.exe", "powershell.exe", "wscript.exe", "mshta.exe"}

    if ctx.name.lower() not in shell_targets:
        return None

    if is_trusted_parent(ctx.parent_name) or not ctx.parent_name:
        return None

    return {
        "rule": "suspicious_parent_spawn",
        "weight": 35,
        "reason": f"{ctx.name} iniciado por {ctx.parent_name}",
        "behavior": (
            f"{ctx.name} foi criado por {ctx.parent_name}, que normalmente "
            f"não inicia processos de shell. Isso quebra o padrão esperado "
            f"de parent-child relationship no Windows."
        ),
        "offensive_context": (
            "Macros maliciosas em documentos Word/Excel abrem cmd.exe ou "
            "PowerShell para executar o payload. Navegadores comprometidos "
            "fazem o mesmo. Detectar o processo pai inesperado é uma das "
            "formas mais confiáveis de identificar execução inicial — T1566 no MITRE ATT&CK."
        ),
        "mitre": "T1566"
    }