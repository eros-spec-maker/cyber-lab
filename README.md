# Cyber Lab

Laboratório educacional para exercícios defensivos, DFIR, forense digital, OSINT e testes autorizados. Use apenas dados sintéticos ou sistemas próprios, com escopo e autorização documentados.

## Estrutura

- `tools/forensics/`: utilitários locais de triagem e integridade de arquivos.
- `tools/osint/`: utilitários para fontes públicas, respeitando termos e privacidade.
- `dfir/`, `forense/`, `osint/`, `defensiva/` e `pentest-autorizado/`: roteiros e material de estudo por área.
- `docs/laboratorio/`: procedimentos, limites e documentação de evidências.
- `tests/`: testes com dados sintéticos.

## Primeira ferramenta: manifesto SHA-256

```sh
python3 tools/forensics/hash_manifest.py ./sample-evidence --output ../manifest.json
```

A ferramenta lê arquivos em blocos, ignora links simbólicos, não altera o conteúdo e recusa sobrescrever o manifesto. A leitura pode atualizar metadados de acesso conforme o sistema de arquivos. Guarde o manifesto separadamente e proteja-o contra alterações. Consulte [preservação de evidências](docs/laboratorio/preservacao-de-evidencias.md) e [hashes e cadeia de custódia](docs/laboratorio/hashes-e-cadeia-de-custodia.md).

Execute os testes com a biblioteca padrão:

```sh
python3 -m unittest discover -s tests -v
```

## Ferramenta existente

`tools/metasploit.sh` é um instalador de terceiros voltado a Termux: instala pacotes, altera arquivos do ambiente, remove uma instalação anterior no caminho configurado e clona código externo. Revise o conteúdo e valide o escopo antes de executá-lo. Este laboratório não recomenda executar ferramentas contra sistemas sem autorização explícita.
