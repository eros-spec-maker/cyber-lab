# Hashes e cadeia de custódia

`tools/forensics/hash_manifest.py` calcula SHA-256 e tamanho em bytes de arquivos regulares, em blocos, e grava os caminhos relativos em JSON ordenado. Links simbólicos são ignorados para evitar leitura de destinos fora do escopo. O programa não armazena nem altera o conteúdo e recusa sobrescrever saídas existentes, inclusive em colisões concorrentes na criação final. Compara a identidade do arquivo observado com o objeto aberto e verifica tamanho, `mtime` e `ctime` antes/depois da leitura para detectar alterações observáveis.

```sh
python3 tools/forensics/hash_manifest.py ./sample-evidence --output ../manifest.json
```

Um hash permite detectar diferenças entre bytes comparados; sozinho, não prova autenticidade, origem, horário de aquisição ou cadeia de custódia. As verificações de mudança não são um bloqueio: um escritor concorrente pode alterar o conteúdo e a ferramenta não cria snapshot da árvore. Mudanças concorrentes em diretórios durante a enumeração podem tornar o inventário inconsistente; prefira mídia montada somente leitura ou uma cópia estável. A ferramenta não substitui imagem forense, bloqueador de escrita ou procedimento institucional validado. A leitura pode atualizar `atime`. Armazene o manifesto separadamente do material examinado, restrinja escrita e registre sua própria transferência e verificação. O timestamp do JSON é o horário local do processo convertido para UTC, não o horário de aquisição da evidência.
