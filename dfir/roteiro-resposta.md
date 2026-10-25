# Roteiro de resposta a incidentes

## Preparação

- Defina contatos, autoridade de decisão, ativos críticos, fontes de log e critérios de escalonamento.
- Confirme autorização, janela, limites e forma segura de armazenar evidências.
- Registre horário local, fuso e desvio conhecido dos relógios envolvidos.

## Detecção e triagem

- Registre alerta original, fonte, horário de recebimento e analista.
- Valide escopo e impacto sem alterar o sistema investigado.
- Preserve logs e contexto antes de contenção que possa destruir dados voláteis.
- Formule hipóteses concorrentes e marque claramente o que é fato, inferência e desconhecido.

## Contenção, erradicação e recuperação

- Obtenha aprovação do responsável antes de ações que afetem disponibilidade.
- Registre cada ação, executor, horário, justificativa e resultado.
- Preserve cópias verificadas; valide backups e monitore reincidência após recuperação.

## Encerramento

- Mantenha cadeia de custódia e controle de acesso aos artefatos.
- Documente limitações, decisões, impacto e lições aprendidas.
- Não publique logs ou indicadores que contenham dados pessoais ou segredos.
