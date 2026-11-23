"""Inventario local, descubrimiento de servicios y selección de archivos."""

import os
import re
from dataclasses import dataclass
from pathlib import Path

SOURCE = {
    ".py": "Python", ".java": "Java", ".js": "JavaScript", ".mjs": "JavaScript",
    ".cjs": "JavaScript", ".jsx": "JavaScript", ".ts": "TypeScript", ".tsx": "TypeScript",
    ".mts": "TypeScript", ".cts": "TypeScript",
}
CONFIG = {".yaml": "YAML", ".yml": "YAML", ".properties": "Properties", ".json": "JSON",
          ".xml": "XML", ".toml": "TOML", ".gradle": "Gradle", ".ini": "INI"}
MANIFESTS = {
    "pom.xml": "Java", "build.gradle": "Java", "build.gradle.kts": "Java",
    "requirements.txt": "Python", "pyproject.toml": "Python", "pipfile": "Python",
    "package.json": "Node.js", "tsconfig.json": "TypeScript", "dockerfile": "Docker",
}
DEPENDENCIES = {"requirements.txt", "pipfile", "pipfile.lock", "build.gradle.kts"}
COMPOSE = {"compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"}
IGNORED = {
    "node_modules", "__pycache__", ".git", ".venv", "venv", "site-packages",
    "target", "dist", "build", "vendor", "coverage", ".gradle", ".tox", "reportes",
}
MAX_BYTES = 1_000_000
SERVICE_KEY = re.compile(r"^([A-Za-z0-9_.-]+)\s*:(?:\s|$)")


@dataclass(frozen=True)
class Inventory:
    files: list
    services: dict
    skipped: list


def is_link(path):
    return path.is_symlink() or getattr(path, "is_junction", lambda: False)()


def read_source(path):
    with path.open("rb") as handle:
        raw = handle.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Archivo mayor a 1 MB")
    if b"\x00" in raw:
        raise ValueError("Archivo no textual")
    return raw.decode("utf-8-sig", errors="replace")


def identify(path):
    name = path.name.lower()
    suffix = path.suffix.lower()
    if suffix in SOURCE and not name.endswith(".min.js"):
        return SOURCE[suffix]
    if name == "dockerfile" or name.startswith("dockerfile."):
        return "Dockerfile"
    if name in DEPENDENCIES or name.startswith("requirements") and suffix == ".txt":
        return "Dependencies"
    if suffix in CONFIG and not name.endswith(".min.json"):
        return CONFIG[suffix]
    return None


def compose_builds(text):
    """Lee el subconjunto de Compose que declara servicios y builds locales."""
    within_services = False
    service_indent = None
    current = None
    build_indent = None
    builds = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        indent = len(raw_line) - len(raw_line.lstrip())
        if indent == 0:
            within_services = line.split("#", 1)[0].strip() == "services:"
            current = None
            service_indent = None
            build_indent = None
            continue
        if not within_services:
            continue
        if service_indent is None:
            service_indent = indent
        if indent == service_indent:
            match = SERVICE_KEY.match(line)
            current = match.group(1) if match else None
            build_indent = None
            if current:
                builds[current] = None
            continue
        if build_indent is not None and indent <= build_indent:
            build_indent = None
        if current and (line.startswith("build:") or (build_indent is not None and line.startswith("context:"))):
            value = line.split(":", 1)[1].split(" #", 1)[0].strip().strip("\"'")
            if line.startswith("build:") and not value:
                build_indent = indent
            elif value:
                builds[current] = value
    return builds


def inventory(root, output):
    inputs = []
    manifests = {}
    compose = []
    skipped = []
    for base, dirs, names in os.walk(root, followlinks=False):
        directory = Path(base)
        dirs[:] = sorted(
            name for name in dirs if name not in IGNORED and not name.startswith(".")
            and directory / name != output and not is_link(directory / name)
        )
        for name in sorted(names):
            if directory == output and name in {"analisis.json", "analisis.html"}:
                continue
            file = directory / name
            language = identify(file)
            if language is None or is_link(file) or not file.is_file():
                continue
            inputs.append((file, language))
            if name.lower() in MANIFESTS:
                manifests.setdefault(directory, set()).add(MANIFESTS[name.lower()])
            if name.lower() in COMPOSE:
                compose.append(file)
    services = {}
    for specification in compose:
        try:
            declared = compose_builds(read_source(specification))
        except (OSError, ValueError) as error:
            skipped.append({"file": specification.relative_to(root).as_posix(), "reason": str(error)})
            continue
        for name, context in declared.items():
            if context and ("$" in context or "://" in context):
                continue
            path = (specification.parent / (context or name)).resolve()
            if path != root and path.is_relative_to(root) and path.is_dir():
                services.setdefault(path, {"name": name, "technologies": set(), "source": "compose"})

    for directory, technologies in sorted(manifests.items(), key=lambda item: (len(item[0].parts), item[0])):
        if directory == root:
            continue
        ancestor = service_path(directory, services)
        if ancestor is not None:
            services[ancestor]["technologies"].update(technologies)
            continue
        services[directory] = {
            "name": directory.name, "technologies": set(technologies), "source": "manifest",
        }

    if not services and inputs:
        services[root] = {"name": root.name, "technologies": set(manifests.get(root, ())), "source": "project_root"}
    for path, language in inputs:
        service = service_path(path.parent, services)
        if service is not None and language in SOURCE.values():
            services[service]["technologies"].add(language)
    return Inventory(inputs, services, skipped)


def service_path(directory, services):
    return next((path for path in (directory, *directory.parents) if path in services), None)
