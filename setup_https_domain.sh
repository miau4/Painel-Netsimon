#!/bin/bash
# ==========================================
#   PAINEL NETSIMON - HTTPS PRÓPRIO
#   Certificado Let's Encrypt real para
#   acesso via https://painel.netsimon.fun
#   com TLS terminado no próprio servidor
#   (em vez de depender do Cloudflare Flexible)
# ==========================================
# QUANDO USAR:
#   Você já acessa o painel via Cloudflare
#   sem porta — isso é suficiente pra maioria.
#   Use este script APENAS se quiser certificado
#   próprio (ex: modo "Full (strict)" no Cloudflare,
#   ou acesso sem Cloudflare com HTTPS real).
#
# PRÉ-REQUISITO:
#   subdomínio já apontando pro IP desta VPS
#   (pode ser com proxy Cloudflare DESLIGADO
#   temporariamente pra emitir o cert, depois
#   pode religar)
# ==========================================

BASE="/etc/painel"
C=$'\033[1;36m'; G=$'\033[1;32m'; R=$'\033[1;31m'; Y=$'\033[1;33m'; W=$'\033[1;37m'; NC=$'\033[0m'

clear
echo -e "${C}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${C}║${W}     🔒 HTTPS PRÓPRIO — Let's Encrypt + Painel Netsimon  ${C}║${NC}"
echo -e "${C}╚══════════════════════════════════════════════════════════════╝${NC}"

read -p "Digite o subdomínio do painel (ex: painel.netsimon.fun): " DOMAIN
[ -z "$DOMAIN" ] && { echo -e "${R}Cancelado.${NC}"; exit 1; }
read -p "E-mail para o certificado Let's Encrypt: " EMAIL
[ -z "$EMAIL" ] && EMAIL="admin@$DOMAIN"

echo -ne "${W}[1/3] Verificando DNS... ${NC}"
MEU_IP=$(wget -qO- --timeout=5 ipv4.icanhazip.com 2>/dev/null)
DOMAIN_IP=$(getent hosts "$DOMAIN" 2>/dev/null | awk '{print $1}' | head -n1)
[ -z "$DOMAIN_IP" ] && DOMAIN_IP=$(dig +short "$DOMAIN" 2>/dev/null | tail -n1)
if [ "$MEU_IP" != "$DOMAIN_IP" ]; then
    echo -e "${Y}AVISO${NC} — $DOMAIN resolve para ${DOMAIN_IP:-<não resolveu>}, esta VPS é $MEU_IP."
    read -p "Continuar mesmo assim? (s/n): " c; [[ "$c" != "s" ]] && exit 1
else
    echo -e "${G}OK${NC} ($DOMAIN → $MEU_IP)"
fi

echo -e "${W}[2/3] Emitindo certificado Let's Encrypt (modo standalone, porta 8880)...${NC}"
apt install -y certbot &>/dev/null
# Para standalone na 8880, precisamos parar o nginx brevemente
systemctl stop nginx
certbot certonly --standalone --non-interactive --agree-tos \
    -m "$EMAIL" -d "$DOMAIN" \
    --http-01-port 8880 2>&1
CERT_OK=$?
systemctl start nginx

if [ $CERT_OK -ne 0 ] || [ ! -d "/etc/letsencrypt/live/$DOMAIN" ]; then
    echo -e "${R}FALHA ao emitir certificado.${NC}"
    echo -e "${Y}Dica: desative temporariamente o proxy Cloudflare (ícone cinza)${NC}"
    echo -e "${Y}durante a emissão, depois pode religar.${NC}"
    exit 1
fi
echo -e "${G}[OK]${NC} Certificado emitido."

echo -ne "${W}[3/3] Reconfigurando Nginx com HTTPS na porta 8880... ${NC}"

NGINX_LOCATIONS='
    location / { try_files $uri $uri/ /index.html; }

    location /api/ {
        proxy_pass http://127.0.0.1:5001/api/;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 120s;
        proxy_request_buffering off;
    }

    location /device_check.php {
        proxy_pass http://127.0.0.1:5001/device_check.php;
        proxy_set_header Host $host;
    }

    location /downloads/ {
        alias /etc/painel/app_releases/;
        autoindex off;
        add_header Content-Disposition "attachment";
        types { application/vnd.android.package-archive apk; }
        default_type application/vnd.android.package-archive;
    }

    location /terminal/ {
        auth_request /internal/auth_check;
        proxy_pass http://127.0.0.1:7681/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
    }

    location = /internal/auth_check {
        internal;
        proxy_pass http://127.0.0.1:5001/api/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header Cookie $http_cookie;
    }'

cat > /etc/nginx/sites-available/netsimon_web <<EOF
# ── HTTPS próprio na porta 8880 (modo Full/Strict no Cloudflare)
server {
    listen 8880 ssl;
    http2 on;
    server_name $DOMAIN;

    ssl_certificate     /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    root /var/www/html;
    index index.html;
    client_max_body_size 250M;
    add_header X-Frame-Options SAMEORIGIN;
    add_header X-Content-Type-Options nosniff;
$NGINX_LOCATIONS
}

# ── HTTP redirect para HTTPS
server {
    listen 8880;
    server_name $DOMAIN;
    return 301 https://\$host\$request_uri;
}

# ── Porta 81: acesso direto por IP
server {
    listen 81;
    server_name _;
    root /var/www/html;
    index index.html;
    client_max_body_size 250M;
$NGINX_LOCATIONS
}
EOF

nginx -t &>/dev/null && systemctl restart nginx && echo -e "${G}OK${NC}" || { echo -e "${R}FALHA${NC}"; nginx -t; exit 1; }

# Renovação automática (certbot já tem cron, só adicionamos hook de restart)
RENEWAL="/etc/letsencrypt/renewal/$DOMAIN.conf"
if [ -f "$RENEWAL" ] && ! grep -q "post_hook" "$RENEWAL"; then
    sed -i "/\[renewalparams\]/a post_hook = systemctl reload nginx" "$RENEWAL"
fi

echo ""
echo -e "${G}✅ HTTPS PRÓPRIO CONFIGURADO!${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
echo -e "${W} Acesse: ${C}https://$DOMAIN${NC}"
echo -e "${W} No Cloudflare, pode ativar SSL/TLS → Full (strict) agora.${NC}"
echo -e "${C}────────────────────────────────────────────────────────────────${NC}"
