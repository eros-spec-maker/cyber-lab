# Auditoria estática: `tools/metasploit.sh`

**Escopo:** leitura do código em 2026-10-25. O script não foi executado. Esta revisão não confirma comportamento em Termux nem segurança dos repositórios remotos.

## Operações com impacto

| Ação | Impacto e risco |
|---|---|
| `pkg update`, `pkg upgrade` e `pkg install` | Atualiza e instala pacotes no ambiente Termux, com efeitos amplos no dispositivo. |
| `python3 -m pip install requests`, `gem install`, `bundle install/update` | Instala código e dependências remotas; `bundle update` altera dependências resolvidas. |
| `rm -rf ${PREFIX}/opt/metasploit-framework` | Apaga recursivamente o caminho interpolado se existir. A expansão não está entre aspas nem validada; um `PREFIX` incorreto ou inesperado amplia o risco. |
| `git clone ... --depth=1` | Baixa código sem fixar commit, assinatura ou hash; a referência remota pode mudar. |
| `sed -i ... config/application.rb` | Altera arquivo do checkout baixado para desabilitar uma verificação de versão. |
| `ln -sf ... ${PREFIX}/bin/` | Cria ou substitui links simbólicos no diretório de comandos do usuário. |
| `termux-elf-cleaner ...pg_ext.so` | Modifica binários encontrados por glob; os arquivos dependem do estado instalado. |
| `source <(echo ... | base64 -d)` | Decodifica e executa shell no processo atual. O conteúdo é inline, mas essa forma dificulta a revisão. |

## Confiabilidade e endurecimento

- Não há `set -e` ou validação consistente dos códigos de saída; etapas posteriores podem operar após falhas anteriores.
- O script depende de pacotes e dependências remotos sem verificação de integridade explicitada nele.
- Expansões de caminhos e argumentos sem aspas podem falhar com espaços e permitir expansões inesperadas.
- O resultado de `Gemfile.lock` passa por pipelines frágeis para escolher versão; a variável não é validada antes da instalação.
- Modifica código do framework depois de obtê-lo, dificultando reproduzir e auditar o resultado.
- Presume ambiente Termux, comandos, caminhos, conectividade e armazenamento disponíveis.

## Recomendação

Não execute em dispositivo pessoal nem como root. Para avaliação, prefira VM descartável sem dados sensíveis; fixe commit e dependências, verifique assinaturas e hashes por canal independente, valide e restrinja caminhos derivados de `PREFIX`, remova a remoção destrutiva automática e revise cada mutação antes de aplicá-la. Esta auditoria é estática e não substitui revisão de dependências ou análise dinâmica isolada.
