"""Ventanas de análisis y observaciones que se usan como entradas del modelo."""

import re
from bisect import bisect_left, bisect_right
from collections import Counter
from dataclasses import dataclass

# Las expresiones localizan construcciones y controles. No producen etiquetas.
PATTERNS = {
    "lookup": (r"\b(?:findById|findOne|getById|get_object|load_object|lookup|find_by_id|get_record)\b", "Lectura de un objeto por identificador"),
    "owner_scope": (r"\b(?:owner_id|ownerId|tenant_id|tenantId|require_owner|checkOwnership|assert_owner|assertOwner|authorize_object|authorizeObject|findForOwner)\b", "Referencia a un control de propiedad o ámbito"),
    "request_input": (r"\b(?:request|req|params|query|request_id|user_input|inputId|criteria|path_id)\b", "Referencia a entrada o a parámetros de una solicitud"),
    "debug": (r"\b(?:debug|debugMode|debug_mode|enableDebug|show_details|includeStacktrace|tracebacks|DEBUG_ENABLED)\b", "Configuración de depuración o de detalle de errores"),
    "debug_enabled": (r"(?:\b(?:debug|debugMode|debug_mode|enableDebug|show_details|includeStacktrace|tracebacks|DEBUG_ENABLED)\b[\s\"']*[:=(]\s*[\"']?(?:true|on|always|1)\b)", "Activación explícita de depuración o detalle"),
    "debug_disabled": (r"\b(?:debug|debugMode|debug_mode|enableDebug|show_details|includeStacktrace|tracebacks|DEBUG_ENABLED)\b[\s\"']*[:=(]\s*[\"']?(?:false|off|never|0)\b", "Desactivación explícita de depuración o detalle"),
    "transport": (r"\b(?:verify|verify_ssl|verifySSL|rejectUnauthorized|check_hostname|validateCert|validate_certificate|verifyCertificate|setVerify)\b\s*[\"']?\s*[:=(]|\bNODE_TLS_REJECT_UNAUTHORIZED\b", "Opción de verificación del transporte"),
    "transport_disabled": (r"\b(?:verify|verify_ssl|verifySSL|rejectUnauthorized|check_hostname|validateCert|validate_certificate|verifyCertificate|setVerify|NODE_TLS_REJECT_UNAUTHORIZED)\b[\s\"']*[:=(]\s*[\"']?(?:false|off|0)\b", "Verificación de transporte desactivada explícitamente"),
    "transport_enabled": (r"\b(?:verify|verify_ssl|verifySSL|rejectUnauthorized|check_hostname|validateCert|validate_certificate|verifyCertificate|setVerify|NODE_TLS_REJECT_UNAUTHORIZED)\b[\s\"']*[:=(]\s*[\"']?(?:true|on|1)\b", "Verificación de transporte activada explícitamente"),
    "sql": (r"\b(?:select\s+.+?\s+from|executeQuery|execute_sql|prepareStatement|cursor\.execute|db\.query|db\.execute)\b", "Construcción o ejecución de una consulta SQL"),
    "sql_composition": (r"\b(?:select|update|insert|delete)\s+[^\n]{3,220}(?:[\"']\s*(?:\+|\.formatted?\()|\$\{|\{\w+\})", "Composición dinámica de texto SQL"),
    "parameter_binding": (r"\b(?:prepareStatement|bindParam|setString|SqlParameter|bind_value|parameterized|bind)\b|(?:WHERE|VALUES)\s+[^\n]{0,100}(?:\?|\$1\b|%s\b|:value\b)", "Marcador de parámetro o enlace de valores SQL"),
    "token": (r"\b(?:jwt|jsonwebtoken|decodeJwt|verifyJwt|verify_signature|verifySignature|decodeToken|verifyToken|readClaims|validateToken)\b", "Lectura o verificación de un token"),
    "token_decode": (r"\b(?:jwt\.decode|jsonwebtoken\.decode|decodeJwt|decodeToken|readClaims)\b", "Decodificación de los datos del token"),
    "signature_disabled": (r"\b(?:verify_signature|verifySignature)\b[\s\"']*[:=(]\s*[\"']?(?:false|off|0)\b", "Comprobación de firma desactivada explícitamente"),
    "token_verify": (r"\b(?:jwt\.verify|jsonwebtoken\.verify|verifyJwt|verifyToken|validateToken|JWTVerifier|validate_claims|verify_signature|verifySignature)\b", "Referencia a verificación de identidad o firma"),
    "handler": (r"\b(?:except|catch)\b", "Captura de una excepción"),
    "ignored_handler": (r"\b(?:except|catch)\b[^\n]{0,160}(?:\{\s*\}|(?:\{|\n)\s*(?:pass\b|return\s+(?:null|None|undefined|false)\b)|:\s*pass\b)", "Captura vacía o devolución neutra ante una excepción"),
    "error_action": (r"\b(?:raise|throw|logger\.(?:error|warn|exception)|fail_closed|error_response|reportError|handleError)\b", "Acción explícita de gestión del error"),
    "quantity": (r"\b(?:pageSize|page_size|batchSize|batch_size|maxItems|max_items|per_page|fetch_all|fetchAll|findAll|listItems|list_items|fetchPage|fetch_page)\b", "Operación de listado o tamaño de lote"),
    "quantity_bound": (r"\b(?:Math\.min|min|clamp|enforceLimit|validate_limit|enforce_limit|cap_size|capSize|rate_limit)\s*\(", "Acotación explícita del tamaño o frecuencia"),
    "unbounded": (r"\b(?:fetch_all|fetchAll|findAll)\s*\(\s*(?:\)|request\b|req\b)|\b(?:pageSize|page_size|batchSize|batch_size|per_page)\s*[:=]\s*(?:req(?:uest)?\b|params\b|query\b|user_input\b)", "Listado sin límite visible o tamaño tomado de la solicitud"),
}
PATTERNS = {key: (re.compile(pattern, re.IGNORECASE), info) for key, (pattern, info) in PATTERNS.items()}
ANCHORS = set(PATTERNS) - {"owner_scope", "request_input", "error_action", "quantity_bound"}
TOKEN = re.compile(r"[a-zA-Z_$][\w$]*|\d+|[+.:?=]")
STRINGS_AND_COMMENTS = re.compile(
    r'''"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|`(?:\\.|[^`\\])*`|/\*[\s\S]*?\*/|(?://|\#)[^\n]*'''
)


@dataclass(frozen=True)
class Candidate:
    line: int
    end_line: int
    text: str
    observations: dict[str, list[int]]


def without_comments(text):
    def strip_comment(match):
        value = match.group()
        if value.startswith(("#", "//", "/*")):
            return "".join("\n" if char == "\n" else " " for char in value)
        return value

    return STRINGS_AND_COMMENTS.sub(strip_comment, text)


def observations(text):
    newlines = [match.start() for match in re.finditer("\n", text)]
    found = {}
    for key, (pattern, _) in PATTERNS.items():
        lines = [bisect_left(newlines, match.start()) + 1 for match in pattern.finditer(text)]
        if lines:
            found[key] = lines
    return found


def terms(text, language):
    cleaned = without_comments(text)
    tokens = [
        "number" if token.isdecimal() else token.lower()
        for token in TOKEN.findall(cleaned)
    ]
    result = Counter(tokens)
    result.update(f"{left}/{right}" for left, right in zip(tokens, tokens[1:]))
    result[f"language:{language}"] = 1
    for key in observations(cleaned):
        result[f"signal:{key}"] = 4
    return result


def candidates(text):
    cleaned = without_comments(text)
    lines = cleaned.splitlines()
    by_signal = observations(cleaned)
    anchors = sorted({line for key in ANCHORS for line in by_signal.get(key, ())})
    if not anchors:
        return
    groups = [[anchors[0]]]
    for line in anchors[1:]:
        if line - groups[-1][-1] <= 2 and line - groups[-1][0] <= 6:
            groups[-1].append(line)
        else:
            groups.append([line])
    for group in groups:
        start = max(1, group[0] - 2)
        end = min(len(lines), group[-1] + 3)
        evidence = {}
        for key, locations in by_signal.items():
            left = bisect_left(locations, start)
            right = bisect_right(locations, end)
            if right > left:
                evidence[key] = list(dict.fromkeys(locations[left:right]))
        yield Candidate(group[0], group[-1], "\n".join(lines[start - 1:end]), evidence)
