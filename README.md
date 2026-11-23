# VulnMiner

Laboratorio 1 de Desarrollo de Software Seguro. VulnMiner analiza repositorios locales de microservicios en **Java, Python, JavaScript y TypeScript**. Encuentra patrones en código y configuración, aplica un clasificador supervisado multietiqueta y genera reportes OWASP Top 10:2025 y OWASP API Security Top 10:2023.

## Ejecutar en Windows

Se necesita Python 3.10 o posterior. Desde este repositorio, crea el ejecutable local y añade su carpeta a la sesión de PowerShell.

```powershell
py -m lab.package
$env:Path = "$(Join-Path (Get-Location) 'dist');$env:Path"
```

Desde la raíz del proyecto que quieras analizar, ejecuta una instrucción.

```powershell
vulnminer scan . --standards owasp2025,api2023 --format json,html --output ./reportes
```

Para la demostración, desde la raíz de este repositorio tras el paso de preparación.

```powershell
Push-Location examples/demo-microservices
vulnminer scan . --output ./reportes
Pop-Location
```

También se puede ejecutar `py -m vulnminer scan examples/demo-microservices` desde este repositorio. En Linux o macOS, empaqueta con `python3 -m lab.package` y lanza el archivo `dist/vulnminer.pyz` por ruta absoluta desde el proyecto objetivo. Para instalar el comando con el empaquetado estándar, también está disponible `python -m pip install .`.

La CLI usa el [modelo incluido](vulnminer/model.json) directamente, sin dependencias de terceros en producción. Las predicciones se generan localmente leyendo archivos. El resumen de consola enumera los hallazgos y las rutas de los reportes. Puedes pasar un solo estándar o formato con las mismas opciones.

## Estructura del proyecto de demostración

```text
examples/demo-microservices/
├── docker-compose.yml
├── api-gateway/       package.json, src/application.ts
├── user-service/      package.json, src/users.js
├── product-service/   pom.xml, Dockerfile, src/main/java/, application.properties
└── order-service/     requirements.txt, app/orders.py, openapi.yml
```

Los ejemplos son proyectos de inspección estática. Sus servicios y configuraciones permiten verificar la CLI sin levantar contenedores. El descubrimiento usa rutas de construcción locales de Compose y manifiestos como `package.json`, `pom.xml` y `pyproject.toml`. Admite también archivos de configuración YAML, JSON, XML, Properties y Dockerfile, incluidas definiciones de API y manifiestos de dependencias.

## Evidencias del laboratorio

| Entregable | Ruta |
| --- | --- |
| Dataset etiquetado y diccionario | [Dataset JSONL](data/dataset.jsonl) · [Diccionario, fuentes y correspondencias](data/README.md) |
| Fases SEMMA | [Notebooks](notebooks/) · [Código reproducible](lab/) |
| Preprocesamiento | [Columnas](results/features.json) · [Matriz dispersa](results/matrix.jsonl) |
| Modelo y comparación | [Modelo serializado](vulnminer/model.json) · [Evaluación de clasificadores](results/evaluation.json) |
| Demostración y controles | [Reporte HTML](results/demo-microservices/analisis.html) · [Reporte JSON](results/demo-microservices/analisis.json) · [Evaluación de proyectos](results/project_evaluation.json) |
| Informe técnico | [Metodología, arquitectura y resultados](docs/informe.md) |

Reproducir el corpus, entrenamiento, dos pruebas de proyectos y notebooks desde la raíz.

```powershell
py -m lab.notebooks
```

Para ejecutar solo el entrenamiento o solo las pruebas de proyectos se pueden usar `py -m lab.train` y `py -m lab.assess_projects`.

La demostración cubre **6 categorías web y 5 de API**. El catálogo de 20 categorías identifica las nueve no evaluadas. Las etiquetas e indicadores CWE son hipótesis para revisión. La confianza expresa el puntaje del modelo y la severidad estima el impacto según el tipo de hallazgo.
