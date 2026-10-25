# Caso DFIR: sequência de autenticação sintética

## Escopo e objetivo

Exercício inteiramente fictício para praticar preservação, hashing, linha do tempo e comunicação de incerteza. Não há sistema real envolvido. `192.0.2.44` pertence a uma faixa reservada para documentação e não deve ser tratado como indicador de ameaça.

Pergunta: o recorte fornecido demonstra autenticação bem-sucedida após falhas para a mesma conta, host e origem?

## Evidências

| ID | Arquivo | Descrição | Origem declarada |
|---|---|---|---|
| E-01 | `evidencias/auth_events.jsonl` | Três eventos de autenticação sintéticos, em UTC | Gerador manual do exercício |
| E-02 | `evidencias/host_inventory.txt` | Metadados fictícios do ativo e da coleta | Gerador manual do exercício |

Os arquivos são a fonte do exercício. O manifesto versionado em `manifest.sha256.json` registra o snapshot deste material; gere outro manifesto em diretório externo ao examinado para repetir a aquisição. O horário de geração variará.

## Reprodução

Na raiz do repositório:

```sh
python3 tools/forensics/hash_manifest.py \
  dfir/casos/2026-01-acesso-sintetico/evidencias \
  --output /tmp/cyber-lab-case-manifest.json
```

Compare `path`, `size_bytes` e `sha256` do resultado com `manifest.sha256.json`. `generated_at_utc` é esperado variar. A saída deve ficar fora da pasta de evidências e não deve existir previamente.

Para ler os eventos em ordem, sem dependências:

```sh
python3 -c 'import json, pathlib; p=pathlib.Path("dfir/casos/2026-01-acesso-sintetico/evidencias/auth_events.jsonl"); [print(json.dumps(json.loads(line), sort_keys=True)) for line in p.read_text().splitlines()]'
```

## Metodologia

1. Tratar os arquivos como evidência somente leitura e registrar o escopo declarado.
2. Criar manifesto SHA-256 antes da interpretação; verificar os hashes contra o snapshot incluído.
3. Ordenar os eventos pelo timestamp UTC e agrupar por host, conta e origem.
4. Separar observações diretamente presentes nos dados de hipóteses que exigiriam logs adicionais.

## Observações e conclusão

- E-01 contém duas falhas de `analyst-demo` em `ws-014`, provenientes de `192.0.2.44`, separadas por oito segundos.
- Cinquenta e um segundos após a primeira falha (43 segundos após a segunda), E-01 registra sucesso para a mesma conta, host e origem e atribui a sessão fictícia `SYNTH-0007`.
- Portanto, o recorte demonstra uma sequência falha-falha-sucesso nos dados sintéticos. Ele não demonstra que houve atividade maliciosa, uso interativo, execução de comandos, exfiltração ou comprometimento real.

## Limitações e próximos dados

O conjunto é pequeno, criado para treinamento e não possui assinatura do produtor nem cadeia de custódia externa. Não há política de autenticação, telemetria de endpoint, auditoria de sessão, DNS, rede ou confirmação independente de relógio. Em uma investigação real, preservar esses registros adicionais, validar sincronização temporal e entrevistar o proprietário do ativo antes de atribuir intenção ou impacto.

## Registro de custódia do exercício

| Evento | Responsável | Horário UTC | Ação / resultado |
|---|---|---|---|
| Preparação | Autor do laboratório | 2026-01-14T09:20:00Z | Criados dois artefatos fictícios; sem coleta de sistemas reais |
| Integridade | Reprodutor do exercício | preencher ao reproduzir | Registrar comando, versão Python, saída e divergências |
