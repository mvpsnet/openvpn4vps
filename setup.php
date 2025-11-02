<?php
/*
The MIT License (MIT)
Copyright (c) 2022 MVPS LTD - www.mvps.net

Project page: https://github.com/mvpsnet/openvpn4vps

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE
OR OTHER DEALINGS IN THE SOFTWARE.
*/

if (php_sapi_name() !== 'cli') {
    die("This should only be run as cli");
}

require(__DIR__ . "/db.php");

if (empty($argv[1]) || strlen($argv[1]) < 8) {
    die("The password is invalid. It must be at least 8 characters long.\n\tphp setup.php <PASSWORD>");
}
$password = trim($argv[1]);


$r = $db->run("SELECT name FROM sqlite_master WHERE type='table' AND name='config'");
if (count($r) == 0) {
    // Check if easy-rsa is available
    $easyrsa_path = "/usr/share/easy-rsa";
    if (!is_dir($easyrsa_path)) {
        die("Could not find easy-rsa. Make sure openvpn and easy-rsa are installed.");
    }

    $port=rand(20000,60000);

    $net=trim(shell_exec("ip -4 route ls | grep default | grep -Po '(?<=dev )(\\S+)' | head -1"));
    if(empty($net)){
        die("Could not identify the network interface");
    }

    // Initialize PKI directory
    $pki_dir = "/etc/openvpn/server/pki";
    if (!is_dir($pki_dir)) {
        mkdir($pki_dir, 0755, true);
        chown($pki_dir, "www-data");
    }

    // Copy easy-rsa to PKI directory
    shell_exec("cp -r $easyrsa_path/* $pki_dir/ 2>/dev/null");
    
    // Initialize PKI
    shell_exec("cd $pki_dir && ./easyrsa init-pki > /dev/null 2>&1");
    shell_exec("cd $pki_dir && ./easyrsa --batch build-ca nopass > /dev/null 2>&1");
    
    // Generate server certificate
    shell_exec("cd $pki_dir && ./easyrsa --batch build-server-full server nopass > /dev/null 2>&1");
    
    // Generate DH parameters
    shell_exec("cd $pki_dir && ./easyrsa gen-dh > /dev/null 2>&1");
    
    // Generate TA key
    shell_exec("cd $pki_dir && openvpn --genkey --secret ta.key > /dev/null 2>&1");
    
    // Set ownership
    shell_exec("chown -R www-data:www-data $pki_dir");

    $db->run("CREATE TABLE `config` (
      `id` varchar(32) NOT NULL PRIMARY KEY,
      `val` text NOT NULL
    )");
    $db->run("CREATE TABLE `profiles` (
      `name` varchar(64) NOT NULL,
      `cert` text NOT NULL,
      `key` text NOT NULL,
      `ip` varchar(16) NOT NULL,
      `ipv6` varchar(64) NOT NULL,
      `disabled` int(1) default '0' NOT NULL
    )");


    $db->run("CREATE TABLE `logins` (
      `ip` varchar(128) NOT NULL,
      `data` int(11) NOT NULL
    )");

    // Store CA certificate and server certificate paths
    $ca_cert = file_get_contents("$pki_dir/pki/ca.crt");
    $server_cert = file_get_contents("$pki_dir/pki/issued/server.crt");
    $server_key = file_get_contents("$pki_dir/pki/private/server.key");
    $dh_pem = file_get_contents("$pki_dir/pki/dh.pem");
    $ta_key = file_get_contents("$pki_dir/ta.key");

    $db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => base64_encode($ca_cert), ":val2" => base64_encode($ca_cert), ":id" => "ca_cert"]);
    $db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => base64_encode($server_cert), ":val2" => base64_encode($server_cert), ":id" => "server_cert"]);
    $db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => base64_encode($server_key), ":val2" => base64_encode($server_key), ":id" => "server_key"]);
    $db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => base64_encode($dh_pem), ":val2" => base64_encode($dh_pem), ":id" => "dh_pem"]);
    $db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => base64_encode($ta_key), ":val2" => base64_encode($ta_key), ":id" => "ta_key"]);
    $db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => $port, ":val2" => $port, ":id" => "port"]);
    $db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => $net, ":val2" => $net, ":id" => "net"]);
    $db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => "udp", ":val2" => "udp", ":id" => "proto"]);

    // Create OpenVPN server configuration
    $server_conf = "port $port
proto udp
dev tun
ca /etc/openvpn/server/pki/pki/ca.crt
cert /etc/openvpn/server/pki/pki/issued/server.crt
key /etc/openvpn/server/pki/pki/private/server.key
dh /etc/openvpn/server/pki/pki/dh.pem
server 10.190.190.0 255.255.255.0
ifconfig-pool-persist /etc/openvpn/server/ipp.txt
keepalive 10 120
tls-auth /etc/openvpn/server/pki/ta.key 0
cipher AES-256-CBC
auth SHA256
compress lz4-v2
user nobody
group nogroup
tls-version-min 1.2
persist-key
persist-tun
status /var/log/openvpn-status.log
verb 3
client-config-dir /etc/openvpn/ccd
";
    @file_put_contents("/etc/openvpn/server/server.conf", $server_conf);
    
    // Create iptables rules script
    $iptables_script = "#!/bin/bash
iptables -t nat -A POSTROUTING -s 10.190.190.0/24 -o $net -j MASQUERADE
iptables -A FORWARD -i tun0 -o $net -j ACCEPT
iptables -A FORWARD -i $net -o tun0 -j ACCEPT
";
    @file_put_contents("/etc/openvpn/server/iptables.sh", $iptables_script);
    chmod("/etc/openvpn/server/iptables.sh", 0755);
    
echo "The setup has been completed.\n";
    echo "The network interface is: $net\n";
    echo "The OpenVPN port is: $port\n\n";
    
    
    
    
}

$passw=password_hash($password,PASSWORD_ARGON2ID);
$db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => $passw, ':val2' => $passw, ':id' => "password"]);
$db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => "", ":val2" => "", ":id" => "twofa_key"]);
$db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => "0", ":val2" => "0", ":id" => "twofa"]);
$db->run("DELETE from logins");

echo "The password has been set and the 2FA is deactivated.\n";
echo "The login username is: admin\n";
echo "The login password is: $password\n";
