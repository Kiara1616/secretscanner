# SecretScanner

[![CI](https://github.com/Kiara1616/secretscanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Kiara1616/secretscanner/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/secret-scanner-cl.svg)](https://pypi.org/project/secret-scanner-cl/)
[![Python](https://img.shields.io/pypi/pyversions/secret-scanner-cl.svg)](https://pypi.org/project/secret-scanner-cl/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

SecretScanner es una herramienta de código abierto para detectar secretos y credenciales hardcodeadas en código fuente. Incluye una CLI para Python, integración con `pre-commit`, un servidor MCP y una extensión para Visual Studio Code.

## Características

- Analiza archivos individuales o directorios completos.
- Detecta tokens de GitHub y Slack, claves de AWS, JWT, contraseñas, API keys, claves RSA y URL con credenciales.
- Clasifica los hallazgos por severidad y omite directorios y formatos irrelevantes.
- Exporta resultados en JSON o CSV.
- Devuelve un código de salida distinto de cero cuando encuentra secretos, útil para CI.
- Se integra con agentes compatibles con MCP y con hooks de `pre-commit`.

> [!IMPORTANT]
> Los resultados pueden incluir falsos positivos. Revisa cada hallazgo y revoca inmediatamente cualquier credencial real expuesta.

## Instalación

Requiere Python 3.10 o superior.

```bash
pip install secret-scanner-cl
```

También puedes instalarlo en un entorno aislado:

```bash
pipx install secret-scanner-cl
```

## Uso de la CLI

```bash
# Analizar el directorio actual
secret-scanner --path .

# Analizar una ruta y exportar un reporte JSON
secret-scanner --path ./mi-proyecto --output json

# Exportar CSV y mostrar cada archivo procesado
secret-scanner --path ./mi-proyecto --output csv --verbose
```

| Opción | Descripción |
| --- | --- |
| `--path PATH` | Archivo o directorio que se analizará. Es obligatorio. |
| `--output json` | Guarda los hallazgos en `output/report.json`. |
| `--output csv` | Guarda los hallazgos en `output/report.csv`. |
| `--verbose` | Muestra los archivos mientras se procesan. |

El comando termina con código `1` cuando detecta al menos un posible secreto y con código `0` cuando no encuentra ninguno.

## Patrones detectados

| Tipo | Severidad |
| --- | --- |
| GitHub Token | Alta |
| AWS Access Key | Alta |
| API Key genérica | Media |
| Contraseña hardcodeada | Alta |
| JWT | Alta |
| Slack Token | Alta |
| Clave privada RSA | Alta |
| URL con credenciales | Media |

SecretScanner ignora automáticamente directorios como `.git`, `node_modules`, `.venv`, `dist`, `build` y `output`, además de formatos binarios comunes.

## Integración con `pre-commit`

Añade esta configuración a `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/Kiara1616/secretscanner
    rev: v1.0.2
    hooks:
      - id: secret-scanner
```

Después instala el hook:

```bash
pre-commit install
```

## Servidor MCP

El paquete instala el comando `secret-scanner-mcp`, que expone la herramienta mediante entrada y salida estándar (`stdio`).

```json
{
  "mcpServers": {
    "secret-scanner": {
      "command": "secret-scanner-mcp",
      "args": []
    }
  }
}
```

## Extensión de Visual Studio Code

La carpeta `vscode-extension/` contiene una extensión que analiza el archivo activo y señala posibles secretos en el editor. Para usarla:

1. Instala primero la CLI con `pip install secret-scanner-cl`.
2. Descarga el archivo `.vsix` más reciente desde la sección **Assets** del último release.
3. En Visual Studio Code abre **Extensions → ··· → Install from VSIX...**.
4. Ejecuta **SecretScanner: Scan Current File** desde la paleta de comandos.

## Desarrollo

```bash
git clone https://github.com/Kiara1616/secretscanner.git
cd secretscanner
python -m venv .venv

# Windows
.venv\Scripts\activate

# Linux o macOS
source .venv/bin/activate

pip install -r requirements.txt
pip install -e .
pytest
```

Las pruebas exigen al menos 80 % de cobertura sobre el módulo del escáner.

## Publicación

Las versiones estables se publican en [PyPI](https://pypi.org/project/secret-scanner-cl/) y se generan automáticamente cuando se publica un release en GitHub. El número de versión de `pyproject.toml` debe coincidir con el tag del release.

## Licencia

Distribuido bajo la licencia MIT. Consulta [LICENSE](LICENSE).
