<?php
define('IVT', 1);
require __DIR__ . '/lib/core.php';

if (!installed()) json_out(['ok' => false, 'code' => 'setup'], 503);
if (($_SERVER['REQUEST_METHOD'] ?? '') !== 'POST' || ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') !== 'invita') json_out(['ok' => false, 'code' => 'bad_request'], 400);

$raw = file_get_contents('php://input');
if ($raw === false || $raw === '') json_out(['ok' => false, 'code' => 'big'], 413);
$in = json_decode($raw, true);
if (!is_array($in)) json_out(['ok' => false, 'code' => 'bad_request'], 400);
$a = (string) ($in['a'] ?? '');

function str_in(array $in, string $k, int $max): string { return mb_substr((string) ($in[$k] ?? ''), 0, $max); }
function need_user(): array { $u = current_user(); if (!$u) json_out(['ok' => false, 'code' => 'auth'], 401); return $u; }
function need_owner(): array { $u = need_user(); if (!(int) $u['is_owner']) json_out(['ok' => false, 'code' => 'forbidden'], 403); return $u; }
function valid_invite_id($id): bool { return is_string($id) && preg_match('/^[a-z0-9]{4,20}$/', $id) === 1; }
/** may this user manage that invite row? owner: everything; member: only their own */
function can_manage(array $u, ?array $row): bool { return (int) $u['is_owner'] === 1 || ($row && $row['acc_id'] === $u['id']); }

try {
    switch ($a) {
    case 'login': {
        $k = norm_id(str_in($in, 'id', 140)); $pw = (string) ($in['pw'] ?? '');
        $rk = 'login:' . client_ip();
        if (rate_count($rk, 900) >= 10) json_out(['ok' => false, 'code' => 'wait', 'wait' => 300]);
        $u = null;
        if ($k) { $st = db()->prepare("SELECT id, pass_hash, status FROM users WHERE k = ?"); $st->execute([$k]); $u = $st->fetch() ?: null; }
        $hash = $u ? $u['pass_hash'] : '$2y$12$AR5dwRm4evGiFJWPBZv13.w/OQOVv.AP0a3v.vHSnlIeLktrqdxd2';
        $okpw = password_verify($pw, $hash);
        if (!$u || !$okpw) { rate_hit($rk); json_out(['ok' => false, 'code' => 'bad']); }
        if ($u['status'] !== 'active') json_out(['ok' => false, 'code' => 'pending']);
        start_session(); session_regenerate_id(true); $_SESSION['uid'] = $u['id'];
        json_out(['ok' => true]);
    }
    case 'logout': {
        start_session(); $_SESSION = []; session_destroy();
        json_out(['ok' => true]);
    }
    case 'register': {
        $name = trim(str_in($in, 'name', 60)); $k = norm_id(str_in($in, 'id', 140)); $pw = (string) ($in['pw'] ?? '');
        if ($name === '' || !$k || strlen($pw) < 6 || strlen($pw) > 200) json_out(['ok' => false, 'code' => 'invalid']);
        $rk = 'reg:' . client_ip();
        if (rate_count($rk, 3600) >= 6) json_out(['ok' => false, 'code' => 'wait', 'wait' => 600]);
        rate_hit($rk);
        $st = db()->prepare("SELECT id FROM users WHERE k = ?"); $st->execute([$k]);
        if ($st->fetch()) json_out(['ok' => false, 'code' => 'exists']);
        db()->prepare("INSERT INTO users (id, k, name, pass_hash, is_owner, status, created_ms) VALUES (?,?,?,?,0,'pending',?)")
            ->execute([rid(8), $k, $name, password_hash($pw, PASSWORD_DEFAULT), now_ms()]);
        json_out(['ok' => true]);
    }
    case 'acc.create': {
        need_owner();
        $name = trim(str_in($in, 'name', 60)); $k = norm_id(str_in($in, 'id', 140)); $pw = (string) ($in['pw'] ?? '');
        if ($name === '' || !$k || strlen($pw) < 6 || strlen($pw) > 200) json_out(['ok' => false, 'code' => 'invalid']);
        $st = db()->prepare("SELECT id FROM users WHERE k = ?"); $st->execute([$k]); $ex = $st->fetch();
        if ($ex) { // existing (maybe pending): activate and set the new password
            db()->prepare("UPDATE users SET pass_hash = ?, status = 'active', name = ? WHERE id = ?")->execute([password_hash($pw, PASSWORD_DEFAULT), $name, $ex['id']]);
        } else {
            db()->prepare("INSERT INTO users (id, k, name, pass_hash, is_owner, status, created_ms) VALUES (?,?,?,?,0,'active',?)")
                ->execute([rid(8), $k, $name, password_hash($pw, PASSWORD_DEFAULT), now_ms()]);
        }
        json_out(['ok' => true]);
    }
    case 'acc.reset': {
        need_owner(); $id = str_in($in, 'id', 12); $pw = (string) ($in['pw'] ?? '');
        if (strlen($pw) < 6 || strlen($pw) > 200) json_out(['ok' => false, 'code' => 'invalid']);
        db()->prepare("UPDATE users SET pass_hash = ? WHERE id = ?")->execute([password_hash($pw, PASSWORD_DEFAULT), $id]);
        json_out(['ok' => true]);
    }
    case 'acc.approve': {
        need_owner(); db()->prepare("UPDATE users SET status = 'active' WHERE id = ?")->execute([str_in($in, 'id', 12)]);
        json_out(['ok' => true]);
    }
    case 'acc.del': {
        need_owner(); db()->prepare("DELETE FROM users WHERE id = ? AND is_owner = 0")->execute([str_in($in, 'id', 12)]);
        json_out(['ok' => true]);
    }
    case 'save': {
        $u = need_user(); $up = $in['upsert'] ?? []; $rm = $in['remove'] ?? [];
        if (!is_array($up) || !is_array($rm) || count($up) > 20 || count($rm) > 50) json_out(['ok' => false, 'code' => 'invalid']);
        $pdo = db(); $pdo->beginTransaction();
        try {
            foreach ($up as $id => $d) {
                if (!valid_invite_id($id) || !is_array($d)) { $pdo->rollBack(); json_out(['ok' => false, 'code' => 'invalid']); }
                if (!in_array($d['tpl'] ?? '', ['wedding', 'birthday', 'house', 'event'], true)) { $pdo->rollBack(); json_out(['ok' => false, 'code' => 'invalid']); }
                $row = invite_row($id);
                if ($row && !can_manage($u, $row)) { $pdo->rollBack(); json_out(['ok' => false, 'code' => 'forbidden'], 403); }
                $acc = $row ? $row['acc_id'] : ((int) $u['is_owner'] ? '' : $u['id']);
                $created = $row ? (int) $row['created_ms'] : now_ms();
                unset($d['accId'], $d['createdAt'], $d['updatedAt']);
                $d['ownerId'] = $row ? (invite_obj($row)['ownerId'] ?? '') : '';
                $json = json_encode($d, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
                if ($json === false || strlen($json) > 9000000) { $pdo->rollBack(); json_out(['ok' => false, 'code' => 'big'], 413); }
                if ($row) $pdo->prepare("UPDATE invites SET data = ?, updated_ms = ? WHERE id = ?")->execute([$json, now_ms(), $id]);
                else $pdo->prepare("INSERT INTO invites (id, acc_id, data, created_ms, updated_ms) VALUES (?,?,?,?,?)")->execute([$id, $acc, $json, $created, now_ms()]);
            }
            foreach ($rm as $id) {
                if (!valid_invite_id($id)) continue;
                $row = invite_row($id);
                if (!$row) continue;
                if (!can_manage($u, $row)) { $pdo->rollBack(); json_out(['ok' => false, 'code' => 'forbidden'], 403); }
                foreach (['invites' => 'id', 'rsvps' => 'invite_id', 'gifts' => 'invite_id'] as $t => $col)
                    $pdo->prepare("DELETE FROM $t WHERE $col = ?")->execute([$id]);
            }
            $pdo->commit();
        } catch (Throwable $e) { if ($pdo->inTransaction()) $pdo->rollBack(); throw $e; }
        json_out(['ok' => true]);
    }
    case 'rsvp.get': case 'gift.get': {
        $t = $a === 'rsvp.get' ? 'rsvps' : 'gifts'; $id = (string) ($in['invite'] ?? '');
        if (!valid_invite_id($id)) json_out(['ok' => false, 'code' => 'invalid']);
        $st = db()->prepare("SELECT data FROM $t WHERE guest = ? AND invite_id = ?"); $st->execute([guest_uid(), $id]); $r = $st->fetch();
        json_out(['ok' => true, 'reply' => $r ? json_decode($r['data'], true) : null]);
    }
    case 'rsvp.put': {
        $id = (string) ($in['invite'] ?? ''); $r = $in['reply'] ?? null;
        if (!valid_invite_id($id) || !is_array($r) || !invite_row($id)) json_out(['ok' => false, 'code' => 'invalid']);
        $g = guest_uid(); $rk = 'put:' . $g;
        if (rate_count($rk, 3600) >= 40) json_out(['ok' => false, 'code' => 'wait']);
        $name = trim(mb_substr((string) ($r['name'] ?? ''), 0, 80)); $status = ($r['status'] ?? '') === 'yes' ? 'yes' : (($r['status'] ?? '') === 'no' ? 'no' : '');
        $count = $status === 'yes' ? max(1, min(20, (int) ($r['count'] ?? 1))) : 0;
        if ($name === '' || $status === '') json_out(['ok' => false, 'code' => 'invalid']);
        $doc = ['name' => $name, 'status' => $status, 'count' => $count, 'note' => mb_substr(trim((string) ($r['note'] ?? '')), 0, 300), 'at' => now_ms()];
        rate_hit($rk);
        upsert_guest('rsvps', $g, $id, $doc);
        json_out(['ok' => true]);
    }
    case 'gift.put': {
        $id = (string) ($in['invite'] ?? ''); $r = $in['gift'] ?? null;
        if (!valid_invite_id($id) || !is_array($r) || !invite_row($id)) json_out(['ok' => false, 'code' => 'invalid']);
        $g = guest_uid(); $rk = 'put:' . $g;
        if (rate_count($rk, 3600) >= 40) json_out(['ok' => false, 'code' => 'wait']);
        $slip = (string) ($r['slip'] ?? '');
        if ($slip !== '' && (!preg_match('~^data:image/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$~', $slip) || strlen($slip) > 900000)) json_out(['ok' => false, 'code' => 'invalid']);
        $amount = (float) ($r['amount'] ?? 0); if ($amount < 0 || $amount > 1000000000) $amount = 0;
        $doc = ['name' => mb_substr(trim((string) ($r['name'] ?? '')), 0, 80), 'amount' => $amount, 'note' => mb_substr(trim((string) ($r['note'] ?? '')), 0, 300), 'slip' => $slip, 'at' => now_ms()];
        rate_hit($rk);
        upsert_guest('gifts', $g, $id, $doc);
        json_out(['ok' => true]);
    }
    case 'rsvp.list': case 'gift.list': {
        $u = need_user(); $t = $a === 'rsvp.list' ? 'rsvps' : 'gifts'; $key = $t === 'rsvps' ? 'replies' : 'gifts';
        if ((int) $u['is_owner']) { $st = db()->query("SELECT guest, invite_id, data, updated_ms FROM $t"); }
        else { $st = db()->prepare("SELECT x.guest, x.invite_id, x.data, x.updated_ms FROM $t x JOIN invites i ON i.id = x.invite_id WHERE i.acc_id = ?"); $st->execute([$u['id']]); }
        $docs = [];
        foreach ($st->fetchAll() as $r) {
            $g = $r['guest'];
            if (!isset($docs[$g])) $docs[$g] = ['uid' => $g, $key => [], 'updatedAt' => 0];
            $docs[$g][$key][$r['invite_id']] = json_decode($r['data'], true);
            $docs[$g]['updatedAt'] = max($docs[$g]['updatedAt'], (int) $r['updated_ms']);
        }
        json_out(['ok' => true, 'docs' => array_values($docs)]);
    }
    case 'rsvp.rm': case 'gift.rm': {
        $u = need_user(); $t = $a === 'rsvp.rm' ? 'rsvps' : 'gifts'; $id = (string) ($in['invite'] ?? ''); $g = str_in($in, 'guest', 24);
        $row = valid_invite_id($id) ? invite_row($id) : null;
        if (!$row || !can_manage($u, $row)) json_out(['ok' => false, 'code' => 'forbidden'], 403);
        db()->prepare("DELETE FROM $t WHERE guest = ? AND invite_id = ?")->execute([$g, $id]);
        json_out(['ok' => true]);
    }
    default:
        json_out(['ok' => false, 'code' => 'bad_request'], 400);
    }
} catch (Throwable $e) {
    error_log('invita api: ' . $e->getMessage());
    json_out(['ok' => false, 'code' => 'server'], 500);
}

function upsert_guest(string $t, string $g, string $id, array $doc): void {
    $json = json_encode($doc, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    $pdo = db(); $pdo->beginTransaction();
    try {
        $st = $pdo->prepare("SELECT 1 AS x FROM $t WHERE guest = ? AND invite_id = ?"); $st->execute([$g, $id]);
        if ($st->fetch()) $pdo->prepare("UPDATE $t SET data = ?, updated_ms = ? WHERE guest = ? AND invite_id = ?")->execute([$json, now_ms(), $g, $id]);
        else $pdo->prepare("INSERT INTO $t (guest, invite_id, data, updated_ms) VALUES (?,?,?,?)")->execute([$g, $id, $json, now_ms()]);
        $pdo->commit();
    } catch (Throwable $e) { if ($pdo->inTransaction()) $pdo->rollBack(); throw $e; }
}
