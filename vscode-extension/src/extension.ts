import * as vscode from 'vscode';
import { exec } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';

let diagnosticCollection: vscode.DiagnosticCollection;

export function activate(context: vscode.ExtensionContext) {
    console.log('SecretScanner extension is now active!');

    diagnosticCollection = vscode.languages.createDiagnosticCollection('secretScanner');
    context.subscriptions.push(diagnosticCollection);

    // Register manual command
    let disposable = vscode.commands.registerCommand('secretScanner.scanCurrentFile', () => {
        const editor = vscode.window.activeTextEditor;
        if (editor) {
            scanDocument(editor.document);
        }
    });
    context.subscriptions.push(disposable);

    // Automatically scan on save
    vscode.workspace.onDidSaveTextDocument((document) => {
        if (document.uri.scheme === 'file') {
            scanDocument(document);
        }
    });
}

function scanDocument(document: vscode.TextDocument) {
    const workspaceFolder = vscode.workspace.getWorkspaceFolder(document.uri);
    if (!workspaceFolder) { return; }

    const cwd = workspaceFolder.uri.fsPath;
    const reportPath = path.join(cwd, 'output', 'report.json');

    // Clean up old report to avoid reading stale data (since CLI only generates it if findings exist)
    if (fs.existsSync(reportPath)) {
        try {
            fs.unlinkSync(reportPath);
        } catch (e) {
            console.error("Could not delete old report", e);
        }
    }

    // Run the Python CLI tool
    const targetPath = document.fileName;
    const command = `secret-scanner --path "${targetPath}" --output json`;

    exec(command, { cwd }, (error, stdout, stderr) => {
        // Even if there's an error (exit code 1 = secrets found), we still check the report.
        if (fs.existsSync(reportPath)) {
            try {
                const reportContent = fs.readFileSync(reportPath, 'utf8');
                const findings = JSON.parse(reportContent);
                updateDiagnostics(document, findings);
            } catch (err) {
                console.error("Failed to parse report.json", err);
            }
        } else {
            // No report generated implies no secrets found
            diagnosticCollection.set(document.uri, []);
        }
    });
}

function updateDiagnostics(document: vscode.TextDocument, findings: any[]) {
    const diagnostics: vscode.Diagnostic[] = [];

    findings.forEach(finding => {
        // finding.file is relative or absolute, but since we scan a specific file, we assume it matches
        // finding.line is 1-indexed
        const lineIndex = finding.line - 1;
        
        if (lineIndex >= 0 && lineIndex < document.lineCount) {
            const textLine = document.lineAt(lineIndex);
            
            // Create a range that highlights the whole line for simplicity
            const range = new vscode.Range(lineIndex, 0, lineIndex, textLine.text.length);
            
            // Determine severity
            let severity = vscode.DiagnosticSeverity.Warning;
            if (finding.severity === 'HIGH') {
                severity = vscode.DiagnosticSeverity.Error;
            }

            const message = `SecretScanner: [${finding.type}] - Review before committing!`;
            
            const diagnostic = new vscode.Diagnostic(range, message, severity);
            diagnostic.source = 'SecretScanner';
            diagnostics.push(diagnostic);
        }
    });

    diagnosticCollection.set(document.uri, diagnostics);
}

export function deactivate() {
    if (diagnosticCollection) {
        diagnosticCollection.clear();
        diagnosticCollection.dispose();
    }
}
