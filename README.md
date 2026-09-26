# SecretScanner

[![CI](https://github.com/Kiara1616/secretscanner/actions/workflows/ci.yml/badge.svg)](https://github.com/Kiara1616/secretscanner/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/secret-scanner-cl.svg)](https://pypi.org/project/secret-scanner-cl/)
[![Python](https://img.shields.io/pypi/pyversions/secret-scanner-cl.svg)](https://pypi.org/project/secret-scanner-cl/)
[![VS Code Marketplace](https://img.shields.io/visual-studio-marketplace/v/kiara.secret-scanner-pr?label=VS%20Code)](https://marketplace.visualstudio.com/items?itemName=kiara.secret-scanner-pr)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Security policy](https://img.shields.io/badge/security-policy-green.svg)](SECURITY.md)

**Detecta credenciales antes de que lleguen al repositorio.** SecretScanner es un escáner local y de código abierto para encontrar secretos hardcodeados mediante CLI, `pre-commit`, MCP y Visual Studio Code.

```text
$ secret-scanner --path .
[HIGH] GitHub Token · src/config.py:12
[!] 1 posible secreto encontrado
```

> [!IMPORTANT]
> SecretScanner está en fase beta. Sus hallazgos requieren revisión humana: puede producir falsos positivos y no reemplaza la rotación inmediata de una credencial expuesta.

## Por qué SecretScanner

- **Local primero:** el código y los hallazgos permanecen en tu equipo.
- **Un motor, varios flujos:** CLI, hook de Git, servidor MCP y extensión para VS Code.
- **Listo para automatización:** códigos de salida apropiados y reportes JSON o CSV.
- **Políticas por proyecto:** exclusiones, allowlists y baseline versionables.
- **Privacidad verificable:** cada hallazgo tiene un fingerprint sin almacenar el secreto.
- **Multiplataforma:** compatible con Windows, Linux y macOS mediante Python 3.10 o posterior.

## Inicio rápido

Instala el paquete desde PyPI:

```bash
pip install secret-scanner-cl
secret-scanner --path .
```

También puedes mantenerlo aislado con `pipx install secret-scanner-cl`.

### Comandos

```bash
# Analizar un archivo o directorio
secret-scanner --path ./mi-proyecto

# Exportar los hallazgos
secret-scanner --path . --output json
secret-scanner --path . --output csv

# Mostrar cada archivo procesado
secret-scanner --path . --verbose

# Crear un baseline con los hallazgos existentes
secret-scanner --path . --update-baseline
```

| Opción | Descripción |
| --- | --- |
| `--path PATH` | Archivo o directorio que se analizará. |
| `--output json` | Guarda los hallazgos en `output/report.json`. |
| `--output csv` | Guarda los hallazgos en `output/report.csv`. |
| `--verbose` | Muestra los archivos a medida que se procesan. |
| `--config PATH` | Utiliza una configuración TOML específica. |
| `--baseline PATH` | Compara contra un baseline específico. |
| `--update-baseline [PATH]` | Crea o reemplaza el baseline. |

El proceso termina con código `1` si encuentra posibles secretos y `0` si no encuentra ninguno, por lo que puede utilizarse como control en CI.

## Configuración por proyecto

Copia [`.secretscanner.example.toml`](https://github.com/Kiara1616/secretscanner/blob/main/.secretscanner.example.toml) como `.secretscanner.toml` en la raíz del proyecto:

```toml
[scan]
exclude_paths = ["vendor/**", "docs/generated/**"]

[allowlist]
paths = ["tests/fixtures/**"]
patterns = ["EXAMPLE_ONLY_[A-Z0-9]+"]
fingerprints = []

[baseline]
path = ".secretscanner-baseline.json"
```

La configuración más cercana al archivo analizado se descubre automáticamente. Las rutas utilizan `/` y aceptan patrones glob. Las expresiones de `allowlist.patterns` se evalúan sobre la línea completa; deben reservarse para valores de ejemplo deliberados.

### Baseline y fingerprints

Cada hallazgo contiene un fingerprint SHA-256 derivado del tipo, la ruta relativa y el valor detectado. El valor original nunca se guarda en el fingerprint ni en el baseline.

Para adoptar SecretScanner en un proyecto con hallazgos conocidos:

```bash
secret-scanner --path . --update-baseline
git add .secretscanner-baseline.json
```

Los análisis posteriores ocultarán esos hallazgos y fallarán únicamente ante secretos nuevos. Revisa siempre el archivo antes de confirmarlo y no uses el baseline para aceptar credenciales reales: deben revocarse y eliminarse.

## Detectores incluidos

| Tipo | Severidad |
| --- | --- |
| Token de GitHub | Alta |
| AWS Access Key | Alta |
| API key genérica | Media |
| Contraseña hardcodeada | Alta |
| JSON Web Token | Alta |
| Token de Slack | Alta |
| Clave privada RSA | Alta |
| URL con credenciales | Media |

El escáner omite `.git`, `node_modules`, entornos virtuales, artefactos de construcción y formatos binarios comunes.

## Pre-commit

Añade el hook al archivo `.pre-commit-config.yaml`. Sustituye `v1.0.2` por el release estable que quieras fijar:

```yaml
repos:
  - repo: https://github.com/Kiara1616/secretscanner
    rev: v1.1.0
    hooks:
      - id: secret-scanner
```

Después ejecuta `pre-commit install`. El hook analiza el repositorio antes de permitir el commit.

## MCP

El comando `secret-scanner-mcp` expone el escáner mediante transporte estándar `stdio`:

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

## Visual Studio Code

Instala [SecretScanner desde Visual Studio Marketplace](https://marketplace.visualstudio.com/items?itemName=kiara.secret-scanner-pr) o ejecuta:

```bash
code --install-extension kiara.secret-scanner-pr
```

La extensión utiliza la CLI local, por lo que también debes instalar el paquete de Python:

```bash
pip install secret-scanner-cl
```

Para generar un VSIX durante el desarrollo:

```bash
cd vscode-extension
npm ci
npm run package
```

## Desarrollo

```bash
git clone https://github.com/Kiara1616/secretscanner.git
cd secretscanner
python -m venv .venv
python -m pip install -e ".[dev]"
pytest
ruff check .
```

La matriz de CI valida Python 3.10–3.13, cobertura mínima de 80 %, estilo, compilación de la extensión y distribuciones para PyPI. Consulta [CONTRIBUTING.md](CONTRIBUTING.md) antes de enviar cambios.

## Seguridad y soporte

No publiques credenciales reales en issues, ejemplos ni reportes. Las vulnerabilidades deben comunicarse en privado siguiendo [SECURITY.md](SECURITY.md). Para preguntas de uso consulta [SUPPORT.md](SUPPORT.md).

## Estado del proyecto

La hoja de ruta inmediata incluye historial Git, detección por entropía y salida SARIF. Consulta [CHANGELOG.md](CHANGELOG.md) para conocer los cambios publicados.

## Licencia

SecretScanner se distribuye bajo la [licencia MIT](LICENSE).
