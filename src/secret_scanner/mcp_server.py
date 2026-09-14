"""
mcp_server.py - Servidor MCP para SecretScanner.
Expone la funcionalidad de escaneo como una herramienta para Agentes de IA.
"""

from mcp.server.fastmcp import FastMCP
from secret_scanner.scanner.file_scanner import scan_path

# Inicializar el servidor MCP
mcp = FastMCP("SecretScanner")

@mcp.tool()
def scan_secrets(target_path: str) -> str:
    """
    Escanea un directorio o archivo en busca de contraseñas, tokens y claves API hardcodeadas.
    
    Args:
        target_path: Ruta absoluta o relativa al archivo o carpeta que se desea analizar.
        
    Returns:
        Un resumen en texto plano de los secretos encontrados.
    """
    try:
        findings = scan_path(target_path, verbose=False)
    except Exception as e:
        return f"Error al escanear la ruta '{target_path}': {str(e)}"
    
    if not findings:
        return f"No se encontraron secretos en '{target_path}'. ¡El código está limpio!"
    
    report = f"¡Alerta! Se encontraron {len(findings)} secreto(s) en '{target_path}':\n\n"
    for f in findings:
        severity = f.get('severity', 'UNKNOWN')
        sec_type = f.get('type', 'Unknown')
        file_path = f.get('file', 'Unknown')
        line = f.get('line', '?')
        content = f.get('content', '')
        
        report += f"- [{severity}] {sec_type} en {file_path}:{line}\n"
        report += f"  Contenido: {content}\n\n"
        
    return report

def main():
    """Punto de entrada principal para el servidor MCP."""
    mcp.run()

if __name__ == "__main__":
    main()
