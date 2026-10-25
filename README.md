# Cyber Lab

Laboratório educacional para DFIR, forense digital, OSINT, defesa e testes autorizados. O repositório prioriza exercícios reproduzíveis, integridade dos artefatos e limites de autorização. Não inclua evidências reais, dados pessoais, credenciais ou segredos.

## Comece aqui

- [Caso DFIR sintético: sequência de autenticação](dfir/casos/2026-01-acesso-sintetico/README.md) — evidências fictícias, manifesto SHA-256, metodologia, conclusão e limitações.
- [Manifesto SHA-256](tools/forensics/README.md) — inventário local de arquivos regulares sem sobrescrever saídas.
- [Procedimentos de laboratório](docs/laboratorio/) — escopo, coleta, preservação, hashes e limitações.
- [Uso seguro](docs/USO_SEGURO.md) — regras para exercícios autorizados e a demonstração de teclado.

## Manifestar evidências

Use uma cópia de trabalho, quando possível, e armazene a saída fora da árvore examinada:

```sh
python3 tools/forensics/hash_manifest.py ./sample-evidence --output ../manifest.json
```

A ferramenta calcula SHA-256 em blocos, ignora links simbólicos, ordena caminhos e se recusa a substituir um arquivo de saída existente. Detecta substituições e alterações observáveis em arquivos durante a leitura. A leitura pode atualizar metadados de acesso (`atime`); não há snapshot ou bloqueio contra alterações concorrentes, então prefira uma cópia estável. Veja [hashes e cadeia de custódia](docs/laboratorio/hashes-e-cadeia-de-custodia.md).

## Verificação local

Somente biblioteca padrão, exceto a dependência opcional da demonstração de teclado:

```sh
python3 -m unittest discover -s tests -v
```

O workflow GitHub Actions executa os testes e análise CodeQL para Python em pushes, pull requests e agenda semanal.

## Demonstração educacional de teclado

`keylogger_educacional.py` é uma captura local em primeiro plano. Pede confirmação explícita, mostra a atividade, grava no diretório atual e encerra com ESC. Não tem persistência, ocultação, ofuscação ou rede. Use apenas em dispositivo próprio ou com autorização informada; não digite credenciais ou dados reais. Consulte [uso seguro](docs/USO_SEGURO.md).

## Outras áreas

- `dfir/` e `forense/`: resposta a incidentes e fluxo forense.
- `defensiva/`: material defensivo e regras de detecção.
- `osint/` e `tools/osint/`: metodologia e fontes públicas.
- `pentest-autorizado/`: modelo de avaliação com escopo autorizado.
- `tools/metasploit.sh`: instalador de terceiros para Termux; não foi executado. Consulte a [auditoria estática](tools/metasploit-auditoria.md), que descreve alterações amplas no ambiente, remoção recursiva e execução de conteúdo remoto.
