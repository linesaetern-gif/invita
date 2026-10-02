<?php
// Share-preview image (LINE / Facebook): serves the cover or host photo of an invitation.
define('IVT', 1);
require __DIR__ . '/lib/core.php';
if (!installed()) { http_response_code(404); exit; }
$code = (isset($_GET['i']) && is_string($_GET['i']) && preg_match('/^[a-z0-9]{4,20}$/', $_GET['i'])) ? $_GET['i'] : '';
$row = $code !== '' ? invite_row($code) : null;
if (!$row) { http_response_code(404); exit; }
$d = invite_obj($row);
foreach (['cover', 'image'] as $k) {
    $v = (string) ($d[$k] ?? '');
    if (preg_match('~^data:image/(jpeg|png|webp);base64,([A-Za-z0-9+/=]+)$~', $v, $m)) {
        $bin = base64_decode($m[2], true);
        if ($bin === false) continue;
        header('Content-Type: image/' . $m[1]);
        header('Cache-Control: public, max-age=600');
        header('X-Content-Type-Options: nosniff');
        echo $bin; exit;
    }
}
http_response_code(404);
