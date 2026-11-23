"""Catálogos OWASP y metadatos de remediación para las etiquetas evaluadas."""

WEB = {
    "A01:2025": "Broken Access Control",
    "A02:2025": "Security Misconfiguration",
    "A03:2025": "Software Supply Chain Failures",
    "A04:2025": "Cryptographic Failures",
    "A05:2025": "Injection",
    "A06:2025": "Insecure Design",
    "A07:2025": "Authentication Failures",
    "A08:2025": "Software or Data Integrity Failures",
    "A09:2025": "Security Logging and Alerting Failures",
    "A10:2025": "Mishandling of Exceptional Conditions",
}
API = {
    "API1:2023": "Broken Object Level Authorization",
    "API2:2023": "Broken Authentication",
    "API3:2023": "Broken Object Property Level Authorization",
    "API4:2023": "Unrestricted Resource Consumption",
    "API5:2023": "Broken Function Level Authorization",
    "API6:2023": "Unrestricted Access to Sensitive Business Flows",
    "API7:2023": "Server Side Request Forgery",
    "API8:2023": "Security Misconfiguration",
    "API9:2023": "Improper Inventory Management",
    "API10:2023": "Unsafe Consumption of APIs",
}
STANDARDS = {"owasp2025": WEB, "api2023": API}
CATALOG = WEB | API

# Estos metadatos enriquecen etiquetas que ya predijo el modelo.
REMEDIATION = {
    ("A01:2025", "API1:2023"): (
        "CWE-639", "Alta", "Podrían leerse datos de otra cuenta si la operación es accesible.",
        "Verificar propiedad y permisos del objeto en el servidor en cada acceso.",
    ),
    ("A02:2025", "API8:2023"): (
        "CWE-489", "Media", "El modo de depuración podría exponer detalles internos.",
        "Deshabilitar la depuración en despliegues y comprobar la configuración efectiva.",
    ),
    ("A04:2025", "API10:2023"): (
        "CWE-295", "Alta", "Un cliente saliente podría aceptar un certificado no confiable.",
        "Habilitar la validación del certificado y del nombre del servidor. Configurar una CA confiable.",
    ),
    ("A05:2025",): (
        "CWE-89", "Alta", "Una entrada que llega a la consulta podría alterar su interpretación.",
        "Usar consultas parametrizadas y verificar el flujo de las entradas hasta la base de datos.",
    ),
    ("A07:2025", "API2:2023"): (
        "CWE-347", "Alta", "La identidad podría depender de un token sin firma validada.",
        "Validar la firma, el algoritmo permitido, el emisor, la audiencia y el vencimiento.",
    ),
    ("A10:2025",): (
        "CWE-390", "Media", "Ignorar errores puede ocultar fallos y devolver un resultado incoherente.",
        "Manejar el error explícitamente y devolver un estado seguro o propagarlo de forma controlada.",
    ),
    ("API4:2023",): (
        "CWE-770", "Media", "Una operación podría consumir más recursos de los previstos.",
        "Aplicar límites máximos en el servidor y presupuestos de tiempo y consumo.",
    ),
}
BY_LABEL = {label: values for labels, values in REMEDIATION.items() for label in labels}
SEVERITY_ORDER = {"Media": 1, "Alta": 2}
