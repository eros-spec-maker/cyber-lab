# Hashes e cadeia de custódia

`tools/forensics/hash_manifest.py` calcula SHA-256 e tamanho em bytes de arquivos regulares, em blocos, e grava os caminhos relativos em JSON. Links simbólicos são ignorados para evitar leitura de destinos fora do escopo. O programa não armazena nem altera o conteúdo e recusa sobrescrever saídas existentes. A leitura pode atualizar metadados de acesso (`atime`) conforme o sistema de arquivos; use aquisição apropriada e mídia protegida contra escrita quando isso for relevante.

```sh
python3 tools/forensics/hash_manifest.py ./sample-evidence --output ../manifest.json
```

Um hash permite detectar diferenças entre bytes comparados; sozinho, não prova autenticidade, origem, horário de aquisição ou cadeia de custódia. A ferramenta não congela os arquivos durante a leitura e não substitui imagem forense, bloqueador de escrita ou procedimento institucional validado. Armazene o manifesto separadamente do material examinado, restrinja escrita e registre sua própria transferência e verificação.
