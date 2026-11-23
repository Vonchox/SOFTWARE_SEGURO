# Dataset etiquetado

Cada línea de [dataset.jsonl](dataset.jsonl) registra un fragmento de fuente o configuración. Las referencias documentan los controles y debilidades usados para diseñar las muestras. El corpus se compone de fragmentos controlados originales, sin copiar aplicaciones ni usar las muestras de demostración.

## Fuentes y muestreo

- Los catálogos oficiales proporcionan los identificadores y la descripción de las categorías. [OWASP Top 10:2025](https://top10.owasp.org/2025/) · [OWASP API Security Top 10:2023](https://api-security.owasp.org/editions/2023/en/0x11-t10/)
- MITRE CWE proporciona la definición de cada debilidad y la base para etiquetar los pares con y sin control. Cada registro incluye el enlace preciso en `references`. [MITRE CWE List](https://cwe.mitre.org/data/)
- OWASP Benchmark y NIST SARD son fuentes públicas de ejemplos etiquetados que se identificaron durante el diseño. Los casos propios permitieron incluir los cuatro lenguajes, configuraciones y etiquetas API de forma controlada. Las muestras de esas dos colecciones no forman parte de este corpus. [OWASP Benchmark](https://owasp.org/projects/benchmark) · [NIST SARD](https://samate.nist.gov/SARD/)

El [generador](../lab/sample.py) crea pares para siete familias de debilidad. Cambia el lenguaje, el formato, la operación y la convención del proyecto. Cada proyecto de origen permanece completo en su partición. La huella normaliza mayúsculas y espacios para detectar fragmentos repetidos. Se descartan duplicados entre grupos y conflictos de etiquetado antes de ajustar el vocabulario.

| Partición | Proyectos | Registros | Porcentaje |
| --- | ---: | ---: | ---: |
| Entrenamiento | 5 | 620 | 71,4 % |
| Validación | 1 | 124 | 14,3 % |
| Prueba | 1 | 124 | 14,3 % |
| Total | 7 | 868 | 100 % |

El corpus contiene 434 fragmentos vulnerables y 434 no vulnerables. Las particiones comparten el diseño de las familias de control, por lo que la prueba interna mide el desempeño en fragmentos comparables de distinto origen sintético. Los proyectos adicionales de `examples/` sirven para comprobar la integración y analizar errores fuera de ese esquema.

## Diccionario

| Campo | Tipo | Significado |
| --- | --- | --- |
| `id` | Cadena | Identificador estable derivado de la huella del contenido |
| `project` | Cadena | Proyecto de origen utilizado como grupo de partición |
| `scenario` | Cadena | Familia de control de la muestra |
| `language` | Cadena | Lenguaje fuente o formato del archivo |
| `kind` | Cadena | `source` o `configuration` |
| `provenance` | Cadena | Forma de obtención de la muestra |
| `references` | Lista de cadenas | Documentación pública consultada para el diseño y las etiquetas |
| `split` | Cadena | `train`, `validation` o `test` |
| `vulnerable` | Booleano | Presencia de la debilidad según la anotación del escenario |
| `labels` | Lista de cadenas | Etiquetas OWASP del escenario. Vacía para el control |
| `cwe` | Lista de cadenas | Debilidad asociada. Vacía para el control |
| `text` | Cadena | Fragmento analizable |
| `fingerprint` | Cadena | SHA-256 de los símbolos normalizados |

## Correspondencias CWE y OWASP

Las correspondencias aplican al escenario de cada fila. Por ejemplo, un problema de certificado se asocia con API10 cuando afecta al cliente que consume una API. El mismo CWE puede corresponder a otras categorías en otros contextos.

| Debilidad | Escenario anotado | OWASP 2025 | OWASP API 2023 |
| --- | --- | --- | --- |
| [CWE-639](https://cwe.mitre.org/data/definitions/639.html) | Consulta de un objeto por identificador de solicitud sin control de propiedad | A01:2025 | API1:2023 |
| [CWE-489](https://cwe.mitre.org/data/definitions/489.html) | Diagnósticos de depuración habilitados en la configuración del servicio | A02:2025 | API8:2023 |
| [CWE-295](https://cwe.mitre.org/data/definitions/295.html) | Verificación de certificado deshabilitada en un cliente saliente | A04:2025 | API10:2023 |
| [CWE-89](https://cwe.mitre.org/data/definitions/89.html) | Texto dinámico de una consulta SQL a partir de entrada | A05:2025 | — |
| [CWE-347](https://cwe.mitre.org/data/definitions/347.html) | Uso de datos de un token de identidad sin comprobación de firma | A07:2025 | API2:2023 |
| [CWE-390](https://cwe.mitre.org/data/definitions/390.html) | Excepción capturada y descartada | A10:2025 | — |
| [CWE-770](https://cwe.mitre.org/data/definitions/770.html) | Lectura o paginación sin límite aplicado por el servicio | — | API4:2023 |
