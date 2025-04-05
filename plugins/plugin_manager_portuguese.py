# plugins/plugin_manager.py

def register(app):
    from PyQt5.QtWidgets import (
        QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
        QFileDialog, QScrollArea, QMessageBox, QFrame, QLineEdit
    )
    import os
    import json
    import shutil
    import importlib.util
    import requests

    plugin_dir = os.path.join(os.path.dirname(__file__))
    config_path = os.path.join(plugin_dir, "enabled_plugins.json")
    tab = QWidget()
    layout = QVBoxLayout()

    if not hasattr(app, "loaded_plugins"):
        app.loaded_plugins = []

    if not hasattr(app, "plugin_refs"):
        app.plugin_refs = {}

    if os.path.exists(config_path):
        with open(config_path, "r") as f:
            plugin_status = json.load(f)
    else:
        plugin_status = {}

    scroll = QScrollArea()
    scroll_widget = QWidget()
    scroll_layout = QVBoxLayout()

    def save_config():
        with open(config_path, "w") as f:
            json.dump(plugin_status, f, indent=4)

    def activate_plugin(fname):
        if fname in app.plugin_refs:
            QMessageBox.information(tab, "Aviso", f"Plugin '{fname}' já está carregado.")
            return
        try:
            path = os.path.join(plugin_dir, fname)
            spec = importlib.util.spec_from_file_location("plugin", path)
            plugin = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin)

            if not hasattr(plugin, "register"):
                raise Exception("Plugin não possui função 'register(app)'")
            plugin.register(app)

            app.loaded_plugins.append(fname)
            app.plugin_refs[fname] = plugin
            plugin_status[fname] = True
            save_config()
            refresh_ui()
        except Exception as e:
            QMessageBox.critical(tab, "Erro ao ativar", f"{fname}:\n{e}")

    def deactivate_plugin(fname):
        QMessageBox.information(tab, "Desativado", f"O plugin '{fname}' foi desabilitado. Reinicie o app se for visual.")
        plugin_status[fname] = False
        save_config()
        refresh_ui()

    def refresh_ui():
        for i in reversed(range(scroll_layout.count())):
            widget = scroll_layout.itemAt(i).widget()
            if widget:
                widget.setParent(None)

        for fname in sorted(os.listdir(plugin_dir)):
            if fname.endswith(".py") and fname != "plugin_manager.py":
                frame = QFrame()
                frame.setStyleSheet("""
                    QFrame {
                        background-color: #2e2e2e;
                        border: 1px solid #444;
                        border-radius: 8px;
                        padding: 10px;
                        margin-bottom: 8px;
                    }
                    QLabel {
                        color: white;
                    }
                    QPushButton {
                        background-color: #555;
                        color: white;
                        padding: 5px 10px;
                        border-radius: 5px;
                    }
                """)
                frame_layout = QVBoxLayout()

                status = plugin_status.get(fname, True)
                title = QLabel(f"📦 {fname}")
                title.setStyleSheet("font-weight: bold; font-size: 14px;")

                status_label = QLabel("✅ Ativado" if status else "❌ Desativado")
                action_btn = QPushButton("Desativar" if status else "Ativar")
                action_btn.clicked.connect(lambda _, f=fname, s=status: deactivate_plugin(f) if s else activate_plugin(f))

                row = QHBoxLayout()
                row.addWidget(status_label)
                row.addWidget(action_btn)

                frame_layout.addWidget(title)
                frame_layout.addLayout(row)
                frame.setLayout(frame_layout)
                scroll_layout.addWidget(frame)

    def import_plugin():
        file, _ = QFileDialog.getOpenFileName(app, "Importar plugin", "", "Python Files (*.py)")
        if file:
            dst = os.path.join(plugin_dir, os.path.basename(file))
            if os.path.exists(dst):
                QMessageBox.warning(tab, "Aviso", "Esse plugin já existe.")
                return
            try:
                shutil.copy(file, dst)
                plugin_status[os.path.basename(file)] = True
                save_config()
                activate_plugin(os.path.basename(file))
            except Exception as e:
                QMessageBox.critical(tab, "Erro ao importar plugin", str(e))

    def install_from_github():
        url = url_input.text().strip()
        if not url.endswith(".py"):
            QMessageBox.warning(tab, "Erro", "Insira uma URL válida para um arquivo .py")
            return
        try:
            response = requests.get(url)
            response.raise_for_status()
            filename = url.split("/")[-1]
            dst_path = os.path.join(plugin_dir, filename)
            with open(dst_path, "wb") as f:
                f.write(response.content)
            plugin_status[filename] = True
            save_config()
            activate_plugin(filename)
        except Exception as e:
            QMessageBox.critical(tab, "Erro", f"Falha ao baixar o plugin: {e}")

    # Interface
    url_input = QLineEdit()
    url_input.setPlaceholderText("https://raw.githubusercontent.com/user/repo/branch/plugin.py")

    github_btn = QPushButton("🌐 Instalar Plugin via GitHub")
    github_btn.clicked.connect(install_from_github)

    import_btn = QPushButton("📂 Importar novo Plugin (.py)")
    import_btn.setStyleSheet("margin-top: 12px; padding: 8px;")
    import_btn.clicked.connect(import_plugin)

    scroll_widget.setLayout(scroll_layout)
    scroll.setWidgetResizable(True)
    scroll.setWidget(scroll_widget)

    layout.addWidget(scroll)
    layout.addWidget(QLabel("Instalar do GitHub:"))
    layout.addWidget(url_input)
    layout.addWidget(github_btn)
    layout.addWidget(import_btn)
    tab.setLayout(layout)

    # 🔄 Coloca a aba no final
    index = app.tabs.count()
    app.tabs.insertTab(index, tab, "Marketplace de Plugins")
    app.tabs.setCurrentIndex(index)
    refresh_ui()
