<?php
define('IVT', 1);
require __DIR__ . '/lib/core.php';
if (!installed()) { header('Location: install.php'); exit; }

$guest = guest_uid();
$u = current_user();
$code = (isset($_GET['i']) && is_string($_GET['i']) && preg_match('/^[a-z0-9]{4,20}$/', $_GET['i'])) ? $_GET['i'] : '';

$invites = []; $accounts = new stdClass(); $meta = '';
if ($code !== '') {
    $row = invite_row($code);
    if ($row) {
        $o = invite_obj($row);
        $invites[$code] = $o;
        $title = trim((string) ($o['title'] ?? ''));
        $desc = trim(preg_replace('/\s+/u', ' ', (string) ($o['message'] ?? '')));
        $hasImg = (!empty($o['cover']) && is_string($o['cover'])) || (!empty($o['image']) && is_string($o['image']));
        $scheme = is_https() ? 'https' : 'http';
        $host = preg_replace('/[^a-zA-Z0-9.\-:]/', '', (string) ($_SERVER['HTTP_HOST'] ?? ''));
        $meta = '<title>' . htmlspecialchars($title !== '' ? $title : 'invita', ENT_QUOTES, 'UTF-8') . '</title>' .
            '<meta property="og:type" content="website"><meta property="og:title" content="' . htmlspecialchars($title, ENT_QUOTES, 'UTF-8') . '">' .
            '<meta property="og:description" content="' . htmlspecialchars(mb_substr($desc, 0, 160), ENT_QUOTES, 'UTF-8') . '">' .
            ($hasImg ? '<meta property="og:image" content="' . $scheme . '://' . $host . '/og/' . $code . '.jpg"><meta name="twitter:card" content="summary_large_image">' : '') .
            '<meta name="robots" content="noindex">';
    }
} elseif ($u) {
    if ((int) $u['is_owner']) { $st = db()->query("SELECT id, acc_id, data, created_ms, updated_ms FROM invites"); }
    else { $st = db()->prepare("SELECT id, acc_id, data, created_ms, updated_ms FROM invites WHERE acc_id = ?"); $st->execute([$u['id']]); }
    foreach ($st->fetchAll() as $r) $invites[$r['id']] = invite_obj($r);
    if ((int) $u['is_owner']) {
        $accounts = [];
        foreach (db()->query("SELECT id, name, is_owner, status, created_ms FROM users ORDER BY created_ms DESC")->fetchAll() as $r)
            $accounts[$r['id']] = ['n' => $r['name'], 'c' => (int) $r['created_ms'], 'o' => (int) $r['is_owner'] === 1, 'p' => $r['status'] !== 'active'];
        if (!$accounts) $accounts = new stdClass();
    }
}
$data = ['invites' => $invites ?: new stdClass(), 'accounts' => $accounts,
    'me' => ['uid' => $guest, 'role' => $u ? ((int) $u['is_owner'] ? 'admin' : 'member') : null, 'id' => $u['id'] ?? '', 'name' => $u['name'] ?? '']];
$json = json_encode($data, JSON_UNESCAPED_UNICODE | JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_PARTIAL_OUTPUT_ON_ERROR);

$tpl = @file_get_contents(__DIR__ . '/lib/app.html');
if ($tpl === false) { http_response_code(500); echo 'app.html missing'; exit; }
$tpl = str_replace('<!--IVT_HEAD-->', $meta, $tpl);
$tpl = str_replace('__IVT_DATA__', $json, $tpl);
header('Content-Type: text/html; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');
echo $tpl;
