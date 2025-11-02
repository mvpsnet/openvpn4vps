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
session_start();

if (empty($_SESSION['logged']) || empty($_SESSION['timeout']) || empty($_SESSION['ip']) || $_SESSION['logged'] !== 1 || $_SESSION['timeout'] < time() || $_SESSION['ip'] != $_SERVER['REMOTE_ADDR']) {
    header("Location: login.php");
    exit;
}

require("db.php");
$_config = [];
$r = $db->run("SELECT * FROM config");
foreach ($r as $x) {
    $_config[$x['id']] = $x['val'];
}

// just in case the password was changed
if ($_config['password'] != $_SESSION['key']) {
    header("Location: login.php");
    exit;
}

$rewrite_config = false;
$q = $_GET['q'] ?? "";

if ($q == "password") {
    $old_password = $_POST['old_password'];
    $new_password = $_POST['new_password'];
    do {
        if (!csrf_check()) {
            $error_msg = "Invalid csrf token. Please refresh and try again.";
            break;
        }
        if ($new_password != $_POST['repeat_password']) {
            $error_msg = "The new passwords do not match.";
            break;
        }
        if (strlen($new_password) < 8) {
            $error_msg = "The new passwords needs to be at least 8 characters in length.";
            break;
        }
        if (!password_verify($old_password, $_config['password'])) {
            $error_msg = "The old password is incorrect";
            break;
        }

        $passw = password_hash($new_password, PASSWORD_ARGON2ID);
        $_SESSION['key'] = $passw;
        $db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => $passw, ':val2' => $passw, ':id' => "password"]);
        $success_msg = "The password has been changed successfully.";
    } while (0);
}

if ($_config['twofa'] == "0" && $q != "2fa" && csrf_check()) {
    $tfa = new tfa();
    $_config['tfa_key'] = $tfa->getPubKey();
    $db->run("INSERT into config (id,val) VALUES (:id,:val) ON CONFLICT(id) DO UPDATE SET val=:val2", [':val' => $_config['tfa_key'], ':val2' => $_config['tfa_key'], ':id' => "tfa_key"]);
}
if ($_config['twofa'] == "0" && $q == "2fa" && csrf_check()) {
    $tfa = new tfa();

    if ($_POST['tfa'] == $tfa->getOtp($_config['tfa_key'])) {

        $db->run("UPDATE config SET val=1 WHERE id='twofa'");
        $success_msg = "The Two-Factor Authentication has been enabled.";
        $_config['twofa'] = "1";
    } else {
        $error_msg = "Invalid TOTP code.";
    }

}

if ($_config['twofa'] == "1" && $q == "disable2fa" && csrf_check()) {
    $tfa = new tfa();
    if ($_POST['tfa'] == $tfa->getOtp($_config['tfa_key'])) {

        $db->run("UPDATE config SET val=0 WHERE id='twofa'");
        $success_msg = "The Two-Factor Authentication has been disabled.";
        $_config['twofa'] = "0";
    } else {
        $error_msg = "Invalid TOTP code.";
    }
}

if ($q == "add") {
    do {
        if (!csrf_check()) {
            $error_msg = "Invalid csrf token. Please refresh and try again.";
            break;
        }
        $r = $db->run("SELECT COUNT(1) as c from profiles");
        if ($r[0]['c'] > 250) {
            $error_msg = "You've reached the maximum number of active profiles - 250";
            break;
        }
        $r = $db->run("select MAX(rowid) as c FROM profiles");
        if (empty($r[0]['c']) || $r[0]['c'] < 250) {
            $current_id = (empty($r[0]['c']) ? 1 : $r[0]['c']) + 2;
            $current_id = intval($current_id);
            $ip = "10.190.190.$current_id";
        } else {
            for ($i = 2; $i < 254; $i++) {
                $ip = "10.190.190.$i";
                $current_id = $i;
                $x = $db->run("SELECT COUNT(1)  as c FROM profiles WHERE ip=:ip", [':ip' => $ip]);
                if ($x[0]['c'] == 0) {
                    break;
                }
            }
        }
        $current_id = intval($current_id);
        $pki_dir = "/etc/openvpn/server/pki";
        $client_name = "client_" . $current_id;

        // Generate client certificate
        $output = shell_exec("cd $pki_dir && ./easyrsa --batch build-client-full $client_name nopass 2>&1");
        $output_lower=strtolower($output);
        $success_indicators = ["database updated", "data base updated", "success", "signature ok", "certificate is to be certified"];
        $is_success = false;
        if(str_replace($success_indicators,'',$output_lower)!=$output_lower){
            $is_success=true;
        }

        if (!$is_success) {
            $error_msg = "Could not generate the client certificate: " . htmlspecialchars($output);
            break;
        }

        // Read client certificate and key
        $client_cert = file_get_contents("$pki_dir/pki/issued/$client_name.crt");
        $client_key = file_get_contents("$pki_dir/pki/private/$client_name.key");

        if (empty($client_cert) || empty($client_key)) {
            $error_msg = "Could not read the generated certificate files.";
            break;
        }

        $name = htmlspecialchars($_POST['profile_name'], ENT_QUOTES | ENT_HTML5);
        if (empty($name)) {
            $name = "Profile-" . $current_id;
        }
        $ipv6 = "fd42:190:190::" . $current_id;

        $db->run("INSERT into profiles (name,cert,key,ip,ipv6) VALUES (:name, :cert,:key,:ip,:ipv6)",
            [':name' => $name, ":cert" => base64_encode($client_cert), ":key" => base64_encode($client_key), ":ip" => $ip, ":ipv6" => $ipv6]);
        $success_msg = "The OpenVPN profile has been created.";
        $rewrite_config = true;
    } while (0);
}

if ($q == "edit" && csrf_check()) {
    $ip = preg_replace("/[^0-9.]/", "", $_GET['ip']);
    if (!empty($_POST['edit']) && $_POST['edit'] == 1 && !empty($_POST['name'])) {
        $name = htmlspecialchars($_POST['name'], ENT_QUOTES | ENT_HTML5);
        $db->run("UPDATE profiles SET name=:name WHERE ip=:ip", [':name' => $name, ":ip" => $ip]);
    } elseif (!empty($_POST['delete']) && $_POST['delete'] == 1) {
        // Get client name from IP
        $profile = $db->run("SELECT * FROM profiles WHERE ip=:ip", [':ip' => $ip]);
        if (!empty($profile[0])) {
            $ip_parts = explode(".", $ip);
            $client_id = end($ip_parts);
            $client_id = intval($client_id);
            $client_name = "client_$client_id";
            // Revoke certificate
            shell_exec("cd /etc/openvpn/server/pki && ./easyrsa --batch revoke $client_name > /dev/null 2>&1");
            shell_exec("cd /etc/openvpn/server/pki && ./easyrsa gen-crl > /dev/null 2>&1");
            // Copy CRL to server directory
            shell_exec("cp /etc/openvpn/server/pki/pki/crl.pem /etc/openvpn/server/ 2>/dev/null");
        }
        $db->run("DELETE FROM profiles WHERE ip=:ip", [':ip' => $ip]);
        // Remove CCD file
        @unlink("/etc/openvpn/ccd/" . $ip);
        $rewrite_config = true;
    } elseif (!empty($_POST['disable']) && $_POST['disable'] == 1) {
        $db->run("UPDATE profiles SET disabled=1 WHERE ip=:ip", [':ip' => $ip]);
        // Remove CCD file when disabled
        @unlink("/etc/openvpn/ccd/" . $ip);
        $rewrite_config = true;
    } elseif (!empty($_POST['enable']) && $_POST['enable'] == 1) {
        $db->run("UPDATE profiles SET disabled=0 WHERE ip=:ip", [':ip' => $ip]);
        $rewrite_config = true;
    }


}


if ($q == "download" && !empty($_GET['ip'])) {
    $ip = preg_replace("/[^0-9.]/", "", $_GET['ip']);

    $profiles = $db->run("SELECT * FROM profiles WHERE ip=:ip", [':ip' => $ip]);
    if (count($profiles) == 0) {
        die("Invalid profile");
    }

    $profile = $profiles[0];
    header('Content-Type: application/octet-stream');
    header("Content-Transfer-Encoding: Binary");
    header("Content-disposition: attachment; filename=\"$profile[name].ovpn\"");

    $ca_cert = base64_decode($_config['ca_cert']);
    $ta_key = base64_decode($_config['ta_key']);
    $client_cert_raw = base64_decode($profile['cert']);
    $client_key_raw = base64_decode($profile['key']);
    
    // Extract only PEM certificate (between BEGIN and END markers)
    if (preg_match('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $client_cert_raw, $matches)) {
        $client_cert = trim($matches[0]) . "\n";
    } else {
        $client_cert = trim($client_cert_raw) . "\n";
    }
    
    // Extract only PEM private key (between BEGIN and END markers)
    if (preg_match('/-----BEGIN (?:RSA )?PRIVATE KEY-----.*?-----END (?:RSA )?PRIVATE KEY-----/s', $client_key_raw, $matches)) {
        $client_key = trim($matches[0]) . "\n";
    } else {
        $client_key = trim($client_key_raw) . "\n";
    }
    
    // Extract only PEM CA certificate (between BEGIN and END markers)
    if (preg_match('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $ca_cert, $matches)) {
        $ca_cert = trim($matches[0]) . "\n";
    } else {
        $ca_cert = trim($ca_cert) . "\n";
    }
    
    // Extract only PEM TLS auth key (between BEGIN and END markers)
    if (preg_match('/-----BEGIN OpenVPN Static key V1-----.*?-----END OpenVPN Static key V1-----/s', $ta_key, $matches)) {
        $ta_key = trim($matches[0]) . "\n";
    } else {
        $ta_key = trim($ta_key) . "\n";
    }
    
    $server_ip = $_SERVER['SERVER_ADDR'];
    $port = $_config['port'];
    $proto = $_config['proto'] ?? 'udp';

    echo "client
dev tun
proto $proto
remote $server_ip $port
resolv-retry infinite
nobind
persist-key
persist-tun
ca [inline]
cert [inline]
key [inline]
tls-auth [inline] 1
cipher AES-256-CBC
auth SHA256
tls-version-min 1.2
compress lz4-v2
verb 3

<ca>
$ca_cert</ca>
<cert>
$client_cert</cert>
<key>
$client_key</key>
<tls-auth>
$ta_key</tls-auth>
";

    exit;

}

$profiles = $db->run("SELECT * FROM profiles");

if ($rewrite_config == true) {
    // Update CCD files for active profiles
    foreach ($profiles as $profile) {
        $profile['ip'] = preg_replace("/[^0-9.]/", "", $profile['ip']);
        if ($profile['disabled'] == 1) {
            @unlink("/etc/openvpn/ccd/" . $profile['ip']);
            continue;
        }


        // Create CCD file for static IP assignment
        $ccd_content = "ifconfig-push " . $profile['ip'] . " 255.255.255.0\n";
        @file_put_contents("/etc/openvpn/ccd/" . $profile['ip'], $ccd_content);
    }
}

require("template/index.php");
