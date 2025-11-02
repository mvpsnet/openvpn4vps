export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
apt update
apt -y install unattended-upgrades apt-listchanges
echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
dpkg-reconfigure -f noninteractive unattended-upgrades
apt -y install git iptables apache2 php php-sqlite3 openvpn easy-rsa sudo
systemctl enable --now apt-daily.timer
systemctl enable --now apt-daily-upgrade.timer
mkdir -p /etc/openvpn/server
mkdir -p /etc/openvpn/ccd
mkdir -p /etc/openvpn/server/pki
chown www-data:www-data /etc/openvpn
chown www-data:www-data /etc/openvpn/server
chown www-data:www-data /etc/openvpn/ccd
chown www-data:www-data /etc/openvpn/server/pki
a2enmod ssl
a2enmod rewrite
a2ensite default-ssl
echo "<Directory /var/www/html>
AllowOverride All
</Directory>">/etc/apache2/conf-enabled/htaccess.conf
systemctl restart apache2
echo "net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1" >/etc/sysctl.d/openvpn.conf
sysctl --system

echo "[Unit]
Description=Watch /etc/openvpn/server/server.conf for changes

[Path]
PathModified=/etc/openvpn/server/server.conf

[Install]
WantedBy=multi-user.target">/etc/systemd/system/openvpn4vps.path

echo "[Unit]
Description=Reload OpenVPN
After=network.target

[Service]
Type=oneshot
ExecStart=/usr/bin/systemctl restart openvpn@server.service

[Install]
WantedBy=multi-user.target">/etc/systemd/system/openvpn4vps.service

systemctl enable --now apache2
cd /var/www/
# Backup existing html if it exists
if [ -d html ]; then
    mv html html_old_$(date +%s)
fi

git clone https://github.com/mvpsnet/openvpn4vps
mv openvpn4vps html

if [ ! -d html ]; then
    mkdir html
fi
chown -R www-data:www-data html

OVPNPASS=`< /dev/urandom tr -dc _A-Z-a-z-0-9 | head -c16`

sudo -u www-data php /var/www/html/setup.php $OVPNPASS > /dev/null

cat << 'EOF' > /var/www/html/.htaccess
RewriteEngine on
RewriteCond %{HTTPS} off
RewriteCond %{THE_REQUEST} !\s/\.well-known/?[\s] [NC]
RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
EOF

systemctl enable --now openvpn@server

systemctl enable --now openvpn4vps.service
systemctl enable --now openvpn4vps.path

echo "The openvpn4vps password is: $OVPNPASS"
echo "The openvpn4vps username is: admin"

unattended-upgrade > /dev/null &
