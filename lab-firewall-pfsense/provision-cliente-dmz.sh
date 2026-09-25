#!/usr/bin/env bash
# Cliente na DMZ (10.10.20.0/24) — usa o pfSense como gateway para a LAN.
# Sobe um HTTP simples "cliente-dmz" na porta 80 e instala ferramentas de teste
# (curl, ping) para os exercicios de regras de firewall.
#
# Argumentos (passados pelo Vagrantfile):
#   $1 = GATEWAY   -> IP da interface DMZ do pfSense (ex.: 10.10.20.1)
#   $2 = ALVO_LAN  -> IP do cliente-lan (ex.: 10.10.10.50), usado nos testes
#
# OBS: a rota para a LAN so funciona depois que o pfSense estiver ativo como
# gateway (interface DMZ no IP $GATEWAY) e com as regras dos exercicios criadas.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

GATEWAY="${1:-10.10.20.1}"
ALVO_LAN="${2:-10.10.10.50}"

# Rede da LAN derivada do IP alvo (assume /24): usada para a rota estatica.
LAN_NET="$(echo "$ALVO_LAN" | awk -F. '{print $1"."$2"."$3".0/24"}')"

# --- Checagem de conectividade (o provisionamento baixa pacotes pela NAT) ---
if ! curl -fsS --max-time 10 -o /dev/null http://archive.ubuntu.com/ 2>/dev/null; then
  echo "ERRO: sem saida para a internet a partir da VM (NAT)." >&2
  echo "      Verifique a rede NAT do VMware (eth0) e tente de novo." >&2
  exit 1
fi

apt-get update -qq
apt-get install -y -qq curl iputils-ping python3

# --- Descobre a interface do segmento (eth1 = rede host-only da DMZ) --------
# eth0 e a NAT do Vagrant; a segunda interface e a do laboratorio.
IFACE_LAB="$(ip -o -4 addr show | awk '$2 != "lo" {print $2}' | grep -v -E 'eth0|ens.*0$' | head -n1)"
[ -z "$IFACE_LAB" ] && IFACE_LAB="eth1"

# --- Rota para a LAN via o pfSense (idempotente) ----------------------------
# Rota especifica para a LAN, sem mexer na rota default (que sai pela NAT).
# So tem efeito quando o pfSense estiver ativo no IP $GATEWAY.
if ! ip route show | grep -q "^${LAN_NET%/*}/24 "; then
  ip route replace "$LAN_NET" via "$GATEWAY" dev "$IFACE_LAB" || \
    echo "AVISO: nao foi possivel instalar a rota agora (pfSense pode estar inativo)."
else
  ip route replace "$LAN_NET" via "$GATEWAY" dev "$IFACE_LAB" || true
fi

# --- HTTP simples "cliente-dmz" na porta 80 via systemd (idempotente) -------
install -d -m 0755 /var/www/lab
cat > /var/www/lab/index.html <<'HTML'
<!doctype html><html lang="pt-br"><meta charset="utf-8">
<title>cliente-dmz</title>
<h1>cliente-dmz</h1>
<p>Pagina servida pela VM da DMZ (porta 80) para testar regras de firewall.</p>
</html>
HTML

cat > /etc/systemd/system/lab-http.service <<'UNIT'
[Unit]
Description=Lab HTTP simples (cliente-dmz) na porta 80
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=/var/www/lab
ExecStart=/usr/bin/python3 -m http.server 80 --bind 0.0.0.0
Restart=on-failure

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable --now lab-http.service
systemctl restart lab-http.service

# --- Resumo para conferencia ------------------------------------------------
IP_LAB="$(ip -o -4 addr show dev "$IFACE_LAB" | awk '{print $4}' | cut -d/ -f1)"
echo "-------------------------------------------------------------"
echo "OK  cliente-dmz"
echo "    interface do lab : $IFACE_LAB"
echo "    IP na DMZ        : ${IP_LAB:-desconhecido}"
echo "    gateway (pfSense): $GATEWAY"
echo "    rota para a LAN  : $LAN_NET via $GATEWAY"
echo "    alvo na LAN      : $ALVO_LAN"
echo "    HTTP local       : http://${IP_LAB:-127.0.0.1}/  (pagina cliente-dmz)"
echo "    OBS: a rota DMZ->LAN so funciona com o pfSense ativo e as regras criadas."
echo "-------------------------------------------------------------"
