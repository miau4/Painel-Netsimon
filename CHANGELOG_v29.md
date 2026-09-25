# Painel Netsimon — v29 — changelog desta rodada

## 1. Autodiagnóstico mais autônomo, detalhado e interativo
- `proxy` (portas 80/8080) e `limiter` migrados de `screen`/`nohup` para
  serviços **systemd** com `Restart=always` (mesmo modelo já aplicado
  ao `checkuser`). Elimina a causa raiz do incidente
  "proxy fora do ar — reinício falhou".
- Toda falha de restart agora coleta evidência real: status do systemd,
  últimas linhas do log do serviço, e uma dica objetiva da causa mais
  comum — tudo anexado ao próprio incidente.
- Novos botões na tela de Manutenção > Incidentes técnicos:
  **Tentar novamente**, **Diagnosticar** e **Perguntar à IA** (a
  mesma IA já configurada no painel passa a ajudar a resolver
  problemas técnicos do próprio painel, não só o bot do WhatsApp).

## 2. Chave da IA sumindo sozinha — causa raiz corrigida
`save_config()` e outras ~12 funções de gravação de config gravavam
os arquivos sem atomicidade (`open(..., "w")` direto). Um restart do
painel no meio exato de uma escrita corrompia o arquivo, e a
recuperação restaurava o último snapshot válido — que podia ser de
antes da chave ter sido salva. Agora toda gravação é atômica (arquivo
temporário + fsync + `os.replace`).

## 3. Limiter — bloqueio errôneo na troca WiFi ↔ dados móveis
O limiter usava sempre `max(sessões, IPs únicos)`. Numa troca de rede,
o Xray mantém o IP antigo "fantasma" na lista por alguns segundos
mesmo a sessão real já tendo migrado, inflando a contagem de IPs sem
inflar sessões de verdade. Agora só confia no contador de IPs quando
ele bate com o de sessões — sinal de IP fantasma passa a usar o
contador de sessões, mais confiável.

## 4. Logs reorganizados
- Nova aba **Sistema**: eventos de serviço (subiu/caiu/reiniciou),
  config corrompido/recuperado, exceções não tratadas — antes tudo
  isso poluía a aba "Device Check".
- Aba **CheckUser API** agora mostra de fato `checkuser.log` (antes
  mostrava por engano o log do próprio painel).
- Nova aba **Painel (API)** com o log correto do painel.

## 5. Backup "Exportar tudo" — falha silenciosa corrigida
- Backend: cada item do backup é adicionado individualmente ao
  `.tar.gz`; um arquivo problemático é pulado (e registrado) em vez de
  derrubar o backup inteiro sem gerar nada.
- Frontend: `exportSql()`/`exportAll()` agora têm tratamento de erro —
  qualquer falha sempre mostra um toast, nunca mais "não acontece nada".

## 6. Dispositivos — esclarecimento e tentativas bloqueadas
- A tabela de "Dispositivos registrados" agora deixa explícito que é
  um registro de aparelhos que **conseguiram conectar** (desde o
  primeiro acesso), não um log de bloqueios.
- Novo card "🚫 Tentativas bloqueadas (device_hash)" mostra as recusas
  reais (endpoint novo `/api/device/blocked-attempts`), dado que já
  existia no banco mas nunca tinha tela própria.

## 7. Botão ♻️ Renovar (+30 dias)
- Novo botão em Usuários (entre copiar UUID e Opções) e em
  Revendedores (antes de Editar). Soma 30 dias à validade e já
  desbloqueia/reativa automaticamente se estiver bloqueado/suspenso.
  Sincroniza com servidores adicionais, se configurados.

## 8. Diversos
- Ícone da aba "Manutenção" trocado para 🛠️ em todas as páginas.
- `install.sh` atualizado para já criar `proxy@80`, `proxy@8080`,
  `limiter` e `checkuser` como systemd numa instalação nova (sem
  `screen`/`nohup`/crontab), e o menu de terminal (`menu.sh`) também
  atualizado pra ligar/desligar o limiter via `systemctl`.
