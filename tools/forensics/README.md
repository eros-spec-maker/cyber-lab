# Ferramentas forenses

Utilitários locais de triagem. `hash_manifest.py` gera inventário SHA-256 e tamanho em bytes de arquivos regulares, em blocos e com ordem determinística. Ignora links simbólicos e cria o JSON sem substituir saídas existentes. Detecta troca de inode entre enumeração e abertura, além de mudanças observáveis durante a leitura.

```sh
python3 tools/forensics/hash_manifest.py ./evidencias --output ../manifest.json
```

O manifesto fica fora da evidência. A leitura pode atualizar `atime`; a ferramenta não cria snapshot da árvore, então use uma cópia estável. Para o exercício guiado, veja [`dfir/casos/2026-01-acesso-sintetico`](../../dfir/casos/2026-01-acesso-sintetico/README.md). Para limites e custódia, consulte `docs/laboratorio/`.
