# oduo-monitor

Monitor do site ODuo rodando no **GitHub Actions** — always-on, independente de qualquer máquina pessoal. Nasceu depois do incidente em que o certificado ficou **136 dias vencido** sem ninguém ver: não faltou conserto, faltou **alarme que não dependesse do Mac de alguém**.

## O que ele vigia (as 3 coisas que falharam juntas em out/2026)

1. **A página responde** — `GET` completo em cada alvo. Pega queda de **TLS antes do HTTP** (foi o que derrubou).
2. **Prazo do certificado** — avisa com antecedência nas faixas de **21, 7, 3, 1 e 0 dias**, porque a renovação do Let's Encrypt trava em silêncio e só aparece no dia que vence.
3. **Quem está servindo** — se **WordPress** voltar a atender no domínio, é sinal de **DNS revertido**.

Alvos monitorados: `https://www.oduo.com.br/`, `https://oduo.com.br/`, `https://www.oduo.com.br/maquinas`.

## Como avisa

Só na **virada** (caiu / voltou / cruzou faixa de certificado) — alarme que repete a cada run vira ruído e para de ser lido. O estado anterior é guardado no **cache do Actions** (`state.json`) entre execuções.

Canal: **Google Chat** (via webhook). A notificação no macOS do incidente original é local da máquina e não migra pra nuvem — o Chat passa a ser o canal confiável; o Mac pode seguir como reforço secundário, se quiserem.

## Setup (uma vez)

1. **Criar o repo no GitHub** e subir estes arquivos (veja os comandos abaixo).
2. **Adicionar o secret do webhook:** repo → **Settings → Secrets and variables → Actions → New repository secret**
   - Nome: `GCHAT_WEBHOOK`
   - Valor: a URL completa do webhook do Google Chat (a que termina em `...&token=...`).
   - ⚠️ O webhook **nunca** vai no código — só como secret.
3. **Ligar o Actions:** aba **Actions** → habilitar workflows.
4. **Testar o canal:** aba **Actions → monitor-oduo → Run workflow** → marcar *"Enviar mensagem de teste"* → deve chegar um `🧪 Teste...` no Chat.

### Minutos do Actions
Cron de **hora em hora** = ~24 runs/dia (~360 min/mês). Cabe folgado na cota grátis mesmo em repo **privado**. Se um dia quiser detecção de queda mais rápida, aperte o `cron` (`*/30` ou `*/15`) — aí vale reavaliar a cota.

## Ajustes rápidos

- **Cadência:** `cron` em `.github/workflows/monitor.yml`.
- **Faixas de alerta do cert:** `CERT_THRESHOLDS` em `monitor.py`.
- **Alvos:** `HTTP_TARGETS` / `CERT_HOSTS` em `monitor.py`.

## Rodar local (opcional)

```bash
GCHAT_WEBHOOK="https://chat.googleapis.com/..." python monitor.py
# só teste de canal, sem checar nada de verdade:
FORCE_TEST=1 GCHAT_WEBHOOK="..." python monitor.py
```

Sem dependências externas — só a biblioteca padrão do Python 3.
