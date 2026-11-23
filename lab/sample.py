"""Construye el corpus controlado y las particiones por proyecto de origen."""

import hashlib
import re
from collections import Counter

from vulnminer.catalog import REMEDIATION
from vulnminer.features import without_comments

LANGUAGES = ("Python", "Java", "JavaScript", "TypeScript")

# Cada fila representa un proyecto sintético con vocabulario y APIs diferentes.
# Los dos últimos proyectos se reservan completos para validación y prueba.
PROFILES = (
    ("almacen", "findById", "require_owner", "debug", "verify", "jwt.decode", "jwt.verify", "page_size", "train"),
    ("agenda", "get_object", "assertOwner", "debugMode", "verify_ssl", "decodeJwt", "verifyJwt", "pageSize", "train"),
    ("biblioteca", "getById", "checkOwnership", "enableDebug", "rejectUnauthorized", "decodeToken", "verifyToken", "per_page", "train"),
    ("reserva", "findOne", "authorizeObject", "tracebacks", "check_hostname", "readClaims", "validateToken", "batch_size", "train"),
    ("facturacion", "load_object", "authorize_object", "includeStacktrace", "validateCert", "jsonwebtoken.decode", "jsonwebtoken.verify", "batchSize", "train"),
    ("entregas", "find_by_id", "assert_owner", "DEBUG_ENABLED", "validate_certificate", "decodeJwt", "verifyToken", "pageSize", "validation"),
    ("inventario", "get_record", "findForOwner", "show_details", "verifySSL", "decodeToken", "verifyJwt", "batchSize", "test"),
)
SCENARIOS = {
    "ownership": (("A01:2025", "API1:2023"), "API1_2023_Broken_Object_Level_Authorization"),
    "debugging": (("A02:2025", "API8:2023"), "API8_2023_Security_Misconfiguration"),
    "certificate": (("A04:2025", "API10:2023"), "API10_2023_Unsafe_Consumption_of_APIs"),
    "sql": (("A05:2025",), ""),
    "signature": (("A07:2025", "API2:2023"), "API2_2023_Broken_Authentication"),
    "exceptions": (("A10:2025",), ""),
    "pagination": (("API4:2023",), "API4_2023_Unrestricted_Resource_Consumption"),
}
API_REFERENCE = "https://api-security.owasp.org/editions/2023/en/"


def assignment(name, expression, language):
    if language == "Python":
        return f"{name} = {expression}"
    declaration = {"Java": "var", "JavaScript": "const", "TypeScript": "const"}[language]
    suffix = ": unknown" if language == "TypeScript" and name in {"result", "claims", "settings", "client"} else ""
    return f"{declaration} {name}{suffix} = {expression};"


def statement(expression, language):
    return expression if language == "Python" else expression + ";"


def request_expr(language, mode, field):
    if language == "Java":
        method = ("getParameter", "getAttribute")[mode]
        return f'request.{method}("{field}")'
    scope = ("request.params", "req.query")[mode]
    if language == "Python":
        return f'{scope}["{field}"]'
    return f"{scope}.{field}"


def source_fragment(scenario, profile, language, mode, vulnerable):
    project, lookup, owner, debug, tls, decode, verify, quantity, _ = profile
    field = (f"{project}_id", f"{project}_ref")[mode]
    source = request_expr(language, mode, field)
    truth = (str(vulnerable) if language == "Python" else str(vulnerable).lower())
    inverse = (str(not vulnerable) if language == "Python" else str(not vulnerable).lower())
    assign = lambda name, expr: assignment(name, expr, language)
    stmt = lambda expr: statement(expr, language)

    if scenario == "ownership":
        actor = ("principal.ownerId", "session.tenant_id")[mode]
        if mode == 1 and not vulnerable:
            guard = "policy.require_access" if project == "inventario" else owner
            return "\n".join((
                assign("request_id", source), stmt(f"{guard}({actor}, request_id)"),
                assign("result", f"{lookup}(request_id)"),
            ))
        args = "request_id" if vulnerable else f"{actor}, request_id"
        operation = lookup if vulnerable else owner
        return "\n".join((assign("request_id", source), assign("result", f"{operation}({args})")))
    if scenario == "debugging":
        wrapper = ("configureWeb", "configure_service")[mode]
        if language == "Java":
            return "\n".join((stmt(f"settings.{debug}({truth})"), stmt(f"{wrapper}(settings)")))
        argument = f"{debug}={truth}" if language == "Python" else f"{{{debug}: {truth}}}"
        return assign("settings", f"{wrapper}({argument})")
    if scenario == "certificate":
        wrapper = ("providerClient", "create_client")[mode]
        if language == "Java":
            return "\n".join((stmt(f"configuration.{tls}({inverse})"), assign("client", f"{wrapper}(configuration)")))
        argument = f"{tls}={inverse}" if language == "Python" else f"{{{tls}: {inverse}}}"
        return assign("client", f"{wrapper}({argument})")
    if scenario == "sql":
        table = (project, project + "_archive")[mode]
        query = f"SELECT name FROM {table} WHERE ref = "
        if vulnerable:
            expression = f'"{query}" + user_input'
            if mode == 1 and language == "Python":
                expression = f'f"{query}{{user_input}}"'
            elif mode == 1 and language == "Java":
                expression = f'"{query}%s".formatted(user_input)'
            call = {
                "Python": "cursor.execute(sql)",
                "Java": "statement.executeQuery(sql)",
                "JavaScript": "db.query(sql)",
                "TypeScript": "db.execute(sql)",
            }[language]
            body = (assign("sql", expression), stmt(call))
        else:
            placeholder = {"Python": "%s", "Java": "?", "JavaScript": "$1", "TypeScript": "?"}[language]
            call = {
                "Python": "cursor.execute(sql, (user_input,))",
                "Java": "connection.prepareStatement(sql)",
                "JavaScript": "db.query(sql, [user_input])",
                "TypeScript": "db.execute(sql, [user_input])",
            }[language]
            body = (assign("sql", f'"{query}{placeholder}"'), stmt(call))
            if language == "Java":
                body += (stmt("statement.setString(1, user_input)"),)
        return "\n".join((assign("user_input", source), *body))
    if scenario == "signature":
        token = ("headerToken", "sessionToken")[mode]
        operation = decode if vulnerable else verify
        args = token if vulnerable else f"{token}, trustedKey"
        return "\n".join((assign(token, source), assign("claims", f"{operation}({args})")))
    if scenario == "exceptions":
        action = (f"refresh_{project}_cache", f"load_{project}_index")[mode]
        if language == "Python":
            if vulnerable:
                handle = ("    pass", "    return None")[mode]
            else:
                handle = "    logger.exception(error)\n    raise"
            return f"try:\n    {action}()\nexcept RuntimeError as error:\n{handle}"
        clause = "RuntimeException error" if language == "Java" else "error"
        if vulnerable:
            handle = ("{}", "{ return null; }")[mode]
        else:
            handle = "{ throw handleError(error); }"
        return f"try {{ {action}(); }}\ncatch ({clause}) {handle}"
    maximum = (50, 200)[mode]
    value = source if vulnerable else f"enforce_limit({source}, {maximum})"
    return "\n".join((assign(quantity, value), assign("result", f"fetchPage({quantity})")))


def config_fragment(scenario, profile, config_format, vulnerable):
    _, _, _, debug, tls, *_ = profile
    key = debug if scenario == "debugging" else tls
    flag = vulnerable if scenario == "debugging" else not vulnerable
    value = str(flag).lower()
    return {
        "YAML": f"service:\n  {key}: {value}\n",
        "Properties": f"service.{key}={value}\n",
        "JSON": f'{{"service":{{"{key}":{value}}}}}\n',
        "Dockerfile": f"FROM scratch\nENV {key}={value}\n",
    }[config_format]


def fingerprint(text):
    tokens = re.findall(r"\w+|[^\w\s]", without_comments(text))
    normalized = " ".join(token.lower() for token in tokens)
    return hashlib.sha256(normalized.encode()).hexdigest()


def raw_records():
    for profile in PROFILES:
        project, *_, split = profile
        for scenario, (labels, api_page) in SCENARIOS.items():
            cwe = REMEDIATION[labels][0]
            reference = f"https://cwe.mitre.org/data/definitions/{cwe[4:]}.html"
            formats = ("YAML", "Properties", "JSON", "Dockerfile") if scenario in {"debugging", "certificate"} else ()
            for language in (*LANGUAGES, *formats):
                modes = (0, 1) if language in LANGUAGES else (0,)
                for mode in modes:
                    for vulnerable in (True, False):
                        text = (
                            source_fragment(scenario, profile, language, mode, vulnerable)
                            if language in LANGUAGES
                            else config_fragment(scenario, profile, language, vulnerable)
                        )
                        yield {
                            "project": f"controlado-{project}",
                            "scenario": scenario,
                            "language": language,
                            "kind": "source" if language in LANGUAGES else "configuration",
                            "provenance": "fragmento controlado original",
                            "references": [reference] + ([API_REFERENCE + api_page + "/"] if api_page else []),
                            "split": split,
                            "vulnerable": vulnerable,
                            "labels": list(labels) if vulnerable else [],
                            "cwe": [cwe] if vulnerable else [],
                            "text": text,
                            "fingerprint": fingerprint(text),
                        }


def sample():
    groups = {}
    removals = Counter()
    for row in raw_records():
        digest = row["fingerprint"]
        entry = groups.setdefault(digest, {"splits": set(), "truth": set(), "rows": []})
        entry["splits"].add(row["split"])
        entry["truth"].add(tuple(row["labels"]))
        entry["rows"].append(row)
    records = []
    for entry in groups.values():
        if len(entry["truth"]) != 1:
            removals["inconsistent"] += len(entry["rows"])
            continue
        if len(entry["splits"]) != 1:
            removals["cross_split_duplicate"] += len(entry["rows"])
            continue
        row = entry["rows"][0]
        removals["within_split_duplicate"] += len(entry["rows"]) - 1
        if not row["text"].strip():
            removals["empty"] += 1
            continue
        records.append({"id": f"VM-{row['fingerprint'][:12]}", **row})
    splits = {
        name: {row["project"] for row in records if row["split"] == name}
        for name in ("train", "validation", "test")
    }
    if sum(map(len, splits.values())) != len(set().union(*splits.values())):
        raise ValueError("Hay proyectos compartidos entre particiones.")
    if len(records) < 500 or sum(not row["vulnerable"] for row in records) < 100:
        raise ValueError("El corpus limpio no cumple los mínimos del laboratorio.")
    return records, dict(removals)
