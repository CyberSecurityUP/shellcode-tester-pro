#### 🇧🇷 Plugins Personalizados

- Coloque arquivos `.py` dentro da pasta `/plugins`.
- Use a função `register(app)` para injetar funções na interface.
- Plugins com `enabled_plugins.json` controlam ativação por nome.
- É possível importar GUI, funções e objetos da main.

Exemplo:
```python
# plugins/meu_plugin.py
def register(app):
    tab = QWidget()
    layout = QVBoxLayout()
    layout.addWidget(QLabel("Exemplo de Plugin"))
    tab.setLayout(layout)
    app.tabs.addTab(tab, "Meu Plugin")
```

#### 🇺🇸 Custom Plugins

- Place `.py` files inside the `/plugins` folder.
- Use `register(app)` function to hook your plugin.
- `enabled_plugins.json` controls which are loaded.
- You can access main window UI objects.

Example:
```python
# plugins/my_plugin.py
def register(app):
    tab = QWidget()
    layout = QVBoxLayout()
    layout.addWidget(QLabel("Plugin Example"))
    tab.setLayout(layout)
    app.tabs.addTab(tab, "My Plugin")
```
