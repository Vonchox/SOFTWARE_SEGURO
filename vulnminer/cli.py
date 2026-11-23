"""Interfaz ejecutable sin dependencias de terceros durante el análisis."""

import argparse
import sys
from pathlib import Path

from .catalog import STANDARDS
from .model import Model
from .report import save_reports
from .scan import scan


def csv_option(allowed):
    def parse(value):
        options = tuple(dict.fromkeys(token.strip().lower() for token in value.split(",")))
        if not options or not set(options) <= set(allowed):
            raise argparse.ArgumentTypeError(f"Valores permitidos: {', '.join(allowed)}")
        return options
    return parse


def main(argv=None):
    parser = argparse.ArgumentParser(prog="vulnminer", description="Analiza código y configuración local de microservicios.")
    actions = parser.add_subparsers(dest="action", required=True)
    command = actions.add_parser("scan", help="Analizar el directorio raíz de un proyecto")
    command.add_argument("root", nargs="?", default=".", type=Path)
    command.add_argument("--standards", type=csv_option(STANDARDS), default=tuple(STANDARDS))
    command.add_argument("--format", type=csv_option(("json", "html")), default=("json", "html"))
    command.add_argument("--output", default=Path("reportes"), type=Path)
    args = parser.parse_args(argv)
    root = args.root.resolve()
    output = args.output.resolve()
    if not root.is_dir():
        parser.error(f"El directorio del proyecto no existe: {root}")
    try:
        report = scan(root, output, args.standards, Model.load())
        paths = save_reports(report, output, args.format)
    except (OSError, ValueError, KeyError) as error:
        print(f"Error: {error}", file=sys.stderr)
        return 1
    summary = report["summary"]
    print(f"VulnMiner | {report['project']} | modelo: {report['model']['algorithm']}")
    print(f"Microservicios: {summary['services']} | Archivos: {summary['files_analyzed']} | "
          f"Hallazgos potenciales: {summary['potential_findings']} | Pendientes: {summary['pending_review']}")
    for item in report["findings"]:
        labels = ", ".join(item["labels"]) or "Pendiente de revisión"
        print(f"  {item['id']} {item['service']} {item['file']}:{item['line']} [{labels}] "
              f"confianza {item['confidence']:.2f} | severidad {item['severity']}")
    for path in paths:
        print(f"Reporte: {path}")
    return 0
