[![Review Assignment Due Date](https://classroom.github.com/assets/deadline-readme-button-22041afd0340ce965d47ae6ef1cefeee28c7c493a6346c4f15d667ab976d596c.svg)](https://classroom.github.com/a/MQUb8mG3)
[![Open in Codespaces](https://classroom.github.com/assets/launch-codespace-2972f46106e565e64193e422d61a12cf1da4916b45550586e14ef0a7c637dd04.svg)](https://classroom.github.com/open-in-codespaces?assignment_repo_id=23328920)

# SecretScanner — Analizador de Secretos


Herramienta de código abierto desarrollada en **Python 3.10** que analiza proyectos de software y detecta **secretos y credenciales hardcodeadas** (API keys, tokens, contraseñas, claves privadas) mediante expresiones regulares.

## Características

- Soporte para cualquier directorio o archivo de texto.
- Detección automática del tipo de secreto encontrado.
- Recorrido recursivo de directorios con `os.walk`.
- Análisis basado en **8 patrones regex** documentados: GitHub Token, AWS Access Key, API Key genérica, contraseña hardcodeada, JWT Token, Slack Token, clave privada RSA y URL con credenciales.
- Salida en consola con colores diferenciados por severidad.
- Exportación de reportes a **JSON** y **CSV** en la carpeta `output/`.
- Interfaz de línea de comandos (CLI) con `--path`, `--output` y `--verbose`.

## Requisitos

- Python 3.10 o superior
- pip

## Instalación

Instala la herramienta fácilmente desde PyPI usando `pip`:

```bash
pip install secret-scanner-cl
```

*(Opcional) Si usas `pipx` para gestionar herramientas de consola en entornos aislados:*
```bash
pipx install secret-scanner-cl
```

## Uso de la CLI

Una vez instaladas las dependencias, ejecuta la herramienta con:

```bash
python main.py --path <ruta-del-proyecto>
```

## Parámetros y opciones

| Opción | Descripción |
|--------|-------------|
| `--path <ruta>` | **(Requerido)** Ruta al directorio o archivo a analizar |
| `--output json` | Exporta el reporte a `output/report.json` |
| `--output csv` | Exporta el reporte a `output/report.csv` |
| `--verbose` | Muestra cada archivo procesado durante el escaneo |

## Ejemplos

```bash
# Analizar el directorio actual
python main.py --path .

# Analizar una ruta específica y exportar JSON
python main.py --path ./mi_proyecto --output json

# Analizar y exportar CSV
python main.py --path ./mi_proyecto --output csv

# Modo verbose — muestra cada archivo procesado
python main.py --path ./mi_proyecto --verbose

# Modo Verbose + Exportar JSON
python main.py --path ./mi_proyecto --verbose --output json
```

## Integración con Agentes de IA (MCP Skill)

SecretScanner incluye un servidor compatible con el **Model Context Protocol (MCP)**, lo que permite que herramientas de Inteligencia Artificial (como Claude Desktop o Cursor) utilicen este analizador de manera nativa como una "Skill".

Para iniciar el servidor MCP, puedes utilizar el comando global que se instala automáticamente con el paquete:
```bash
secret-scanner-mcp
```
*Nota: Este comando se comunica usando la entrada y salida estándar (`stdio`), diseñado específicamente para ser consumido por un Agente IA, no por humanos.*

### Cómo configurarlo en Claude Desktop / Agentes compatibles
Añade la siguiente configuración al archivo de configuración de tu Agente (ej. `claude_desktop_config.json`):
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

Este proyecto incluye una **Extensión oficial para VSCode** que subraya en rojo los secretos directamente en el código fuente.

### Instalación
1. Dirígete a la carpeta `vscode-extension/` en este repositorio.
2. Encuentra el archivo compilado `secret-scanner-vscode-1.0.0.vsix`.
3. Instálalo en Visual Studio Code: 
   - Abre VSCode > Panel de Extensiones (Ctrl+Shift+X).
   - Haz clic en los tres puntos `...` arriba a la derecha > **Install from VSIX...**
   - Selecciona el archivo `.vsix`.

### Uso
La extensión se activará automáticamente y escuchará cada vez que guardes un archivo (`Ctrl+S`). Si tu archivo contiene una contraseña o un token que rompe las reglas, aparecerá un subrayado rojo (Warning/Error) directamente en el editor. También puedes invocar manualmente el escaneo con el comando de VSCode: `SecretScanner: Scan Current File`.

*(Nota: Debes tener instalado `secret-scanner-cl` globalmente vía `pip` para que la extensión funcione).*

## Integración con `pre-commit` (Git Hooks)

Puedes integrar este escáner de secretos directamente en tu flujo de trabajo de Git utilizando el framework oficial [pre-commit](https://pre-commit.com/). Esto evitará que hagas `git commit` accidentalmente si hay contraseñas en tu código.

Para usarlo, añade lo siguiente a tu archivo `.pre-commit-config.yaml` en tu repositorio:

```yaml
repos:
-   repo: https://github.com/Kiara1616/secret-scanner
    rev: v1.0.0 # Asegúrate de usar la última versión disponible (o la rama main)
    hooks:
    -   id: secret-scanner
```

Luego ejecuta `pre-commit install` en tu terminal para activar el hook.

## Ejemplo de salida
🔍 Analizando: ./mi_proyecto

[ALERTA] GitHub Token encontrado
Archivo : mi_proyecto/config.py
Línea : 12
Contenido: token = "ghp_1234...****"

[ALERTA] Contraseña hardcodeada encontrada
Archivo : mi_proyecto/db.py
Línea : 8
Contenido: password = "****"

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Análisis completado
Archivos analizados : 24
Secretos encontrados : 2
Reporte exportado : output/report.json
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

text

## Tipos de secretos detectados

| Tipo | Patrón detectado |
|------|-----------------|
| GitHub Token | `ghp_`, `gho_`, `ghu_`, `ghs_` |
| AWS Access Key | `AKIA[0-9A-Z]{16}` |
| API Key genérica | `api_key = "..."` |
| Contraseña hardcodeada | `password = "..."` |
| JWT Token | `eyJ...` (header base64) |
| Slack Token | `xox[baprs]-...` |
| Clave privada RSA | `-----BEGIN RSA PRIVATE KEY-----` |
| URL con credenciales | `http://user:pass@host` |

## Archivos ignorados

El escáner omite automáticamente extensiones binarias (`.png`, `.jpg`, `.gif`, `.exe`, `.zip`, `.pdf`) y directorios no relevantes (`.git`, `__pycache__`, `node_modules`, `output`).

## Desarrollo y tests

```bash
# Instalar dependencias de desarrollo
pip install -r requirements-dev.txt

# Ejecutar todos los tests
pytest

# Ver cobertura por módulo
pytest --cov=scanner --cov-report=term-missing

# Tests de un módulo específico
pytest tests/test_patterns.py -v
```

La cobertura mínima requerida es **80%** sobre el paquete `scanner/`.

## CI/CD

El proyecto cuenta con un pipeline de **GitHub Actions** (`.github/workflows/ci.yml`) que se activa en cada `push` y `pull_request` hacia `main`, instala dependencias, ejecuta los tests con cobertura y falla el build si algún test no pasa.

