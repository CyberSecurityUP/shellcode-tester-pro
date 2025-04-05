from PyQt5.QtWidgets import QWidget, QVBoxLayout, QTextEdit, QPushButton, QLabel, QFileDialog
from fpdf import FPDF

def register(app):
    tab = QWidget()
    layout = QVBoxLayout()

    app.pdf_output = QTextEdit()
    app.pdf_output.setReadOnly(True)

    export_btn = QPushButton("Exportar Shellcode e Análises para PDF")
    export_btn.clicked.connect(lambda: export_to_pdf(app))

    layout.addWidget(QLabel("Exportação de Relatório em PDF"))
    layout.addWidget(export_btn)
    layout.addWidget(app.pdf_output)

    tab.setLayout(layout)
    app.tabs.addTab(tab, "Exportar PDF")

def export_to_pdf(app):
    try:
        shellcode = app.shellcode_input.toPlainText().strip()
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Arial", size=12)
        pdf.cell(200, 10, txt="Shellcode Tester Pro - Relatório", ln=True, align="C")
        pdf.ln(10)

        pdf.multi_cell(0, 10, txt=f"Shellcode:")
        pdf.set_font("Courier", size=10)
        pdf.multi_cell(0, 10, txt=shellcode)

        pdf.ln(5)
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, txt="--- Análise Heurística ---")
        pdf.set_font("Courier", size=10)
        pdf.multi_cell(0, 10, txt=app.sandbox_output.toPlainText())

        pdf.ln(5)
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, txt="--- Desofuscação ---")
        pdf.set_font("Courier", size=10)
        pdf.multi_cell(0, 10, txt=app.deob_output.toPlainText())

        pdf.ln(5)
        pdf.set_font("Arial", size=12)
        pdf.multi_cell(0, 10, txt="--- Memória Hex ---")
        pdf.set_font("Courier", size=10)
        pdf.multi_cell(0, 10, txt=app.mem_output.toPlainText())

        file_path, _ = QFileDialog.getSaveFileName(app, "Salvar PDF", "shellcode_report.pdf", "PDF Files (*.pdf)")
        if file_path:
            pdf.output(file_path)
            app.pdf_output.setText(f"[+] Relatório PDF salvo com sucesso: {file_path}")
        else:
            app.pdf_output.setText("[!] Caminho de arquivo não escolhido.")

    except Exception as e:
        app.pdf_output.setText(f"[!] Erro ao gerar PDF: {str(e)}")