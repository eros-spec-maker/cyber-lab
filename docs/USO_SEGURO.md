# Uso seguro da demonstração de teclado

`keylogger_educacional.py` existe para demonstrar, em primeiro plano, como eventos de teclado podem ser registrados localmente. Use somente em computador próprio, VM isolada ou ambiente com autorização explícita e informada. O consentimento digitado no programa não substitui a autorização do proprietário.

Não digite senhas, tokens, dados pessoais ou informações reais durante o exercício. O arquivo `keylog.txt` pode conter texto sensível: não o adicione ao Git, não o compartilhe e apague-o após o exercício conforme as regras do laboratório. A demonstração não tem persistência, modo oculto, ofuscação nem comunicação de rede; ESC encerra a captura.

Os testes usam eventos e caminhos temporários; não iniciam a captura global. Em ambientes sem suporte a `pynput` ou sem interface gráfica compatível, não tente contornar controles do sistema.
