<?php
if (count(get_included_files()) == 1) {
    die("Direct access not allowed");
}
?>
<footer class="bg-white mt-auto">
    <p class="max-w-4xl mx-auto p-6 text-center text-base text-gray-400">
        &copy; <?= date('Y') ?> <a href="https://github.com/mvpsnet/openvpn4vps">OpenVPN4VPS.</a> - Looking for a VPS? Try <a href="https://www.mvps.net">MVPS.net</a>
    </p>
</footer>
