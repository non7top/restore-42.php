<?php

/**
 * restore-42.php — Universal PHP Restore Tool
 * Single-file, Bitrix-compatible format
 * Supports: Bitrix, WordPress, MODX, Webasyst
 */

define('RESTORE_VERSION', '1.0.0');
define('STORED_PASS_HASH', ''); // self-updated on first login — do not edit this line
define('WORK_DIR', __DIR__ . '/.restore');
define('UPLOADS_DIR', WORK_DIR . '/uploads');
define('EXTRACT_DIR', WORK_DIR . '/extract');
define('BACKUPS_DIR', WORK_DIR . '/backups');
define('STATE_FILE', WORK_DIR . '/.state');

error_reporting(E_ALL);
ini_set('display_errors', '0');
set_time_limit(0);
ini_set('memory_limit', '512M');

// No PHP session — auth uses a stateless HMAC-signed cookie instead.

foreach ([WORK_DIR, UPLOADS_DIR, EXTRACT_DIR, BACKUPS_DIR] as $d) {
    if (!is_dir($d)) {
        mkdir($d, 0755, true);
    }
}
// Protect work dir from direct web access
$htFile = WORK_DIR . '/.htaccess';
if (!file_exists($htFile)) {
    file_put_contents($htFile, 'Deny from all');
}
// Clean up chunk files abandoned for more than 1 hour (truly orphaned).
// Do NOT delete recent chunks — they belong to an upload that is in progress.
foreach (glob(UPLOADS_DIR . '/*.chunk*') ?: [] as $orphan) {
    if (time() - filemtime($orphan) > 3600) {
        unlink($orphan);
    }
}

// ── Router ────────────────────────────────────────────────────────────────────

$action = $_REQUEST['action'] ?? '';

if ($action && !in_array($action, ['login', 'check_auth'], true)) {
    requireAuth();
}

switch ($action) {
    case 'login':
        handleLogin();
        break;
    case 'logout':
        handleLogout();
        break;
    case 'check_auth':
        jsonOk(['auth' => isAuth()]);
        break;
    case 'upload':
        handleUpload();
        break;
    case 'list_files':
        handleListFiles();
        break;
    case 'join_parts':
        handleJoinParts();
        break;
    case 'extract':
        handleExtract();
        break;
    case 'scan':
        handleScan();
        break;
    case 'test_db':
        handleTestDb();
        break;
    case 'import_sql':
        handleImportSql();
        break;
    case 'update_config':
        handleUpdateConfig();
        break;
    case 'clear_cache':
        handleClearCache();
        break;
    case 'htaccess':
        handleHtaccess();
        break;
    case 'backup':
        handleBackup();
        break;
    case 'get_state':
        jsonOk(getState());
        break;
    case 'set_state':
        handleSetState();
        break;
    case 'delete_file':
        handleDeleteFile();
        break;
    case 'cancel_upload':
        handleCancelUpload();
        break;
    case 'verify_file':
        handleVerifyFile();
        break;
    case 'download_upstream':
        handleDownloadUpstream();
        break;
    case 'create_admin_script':
        handleCreateAdminScript();
        break;
    case 'download_backup':
        handleDownloadBackup();
        break;
    default:
        showHtml();
        break;
}

// ── Auth ─────────────────────────────────────────────────────────────────────

// ── Stateless HMAC-signed auth cookie ────────────────────────────────────────
// Token: "<expires_unix>.<hmac_sha256(expires|hash, key=hash)>"
// Bound to STORED_PASS_HASH — re-uploading the script invalidates all tokens.
// Sets Secure flag automatically when served over HTTPS.

define('AUTH_COOKIE',  'r42_auth');
define('AUTH_TTL',     604800);      // 7-day token lifetime

function authMakeToken(): string
{
    $exp = time() + AUTH_TTL;
    $sig = hash_hmac('sha256', $exp . '|' . STORED_PASS_HASH, STORED_PASS_HASH);
    return $exp . '.' . $sig;
}

function authVerifyToken(string $token): bool
{
    if (STORED_PASS_HASH === '') {
        return false; // script re-uploaded, no valid password
    }
    $parts = explode('.', $token, 2);
    if (count($parts) !== 2) {
        return false;
    }
    [$exp, $sig] = $parts;
    if ((int)$exp < time()) {
        return false; // expired
    }
    $expected = hash_hmac('sha256', $exp . '|' . STORED_PASS_HASH, STORED_PASS_HASH);
    return hash_equals($expected, $sig);
}

function authSetCookie(): void
{
    $secure = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
           || ($_SERVER['SERVER_PORT'] ?? 80) == 443;
    setcookie(AUTH_COOKIE, authMakeToken(), [
        'expires'  => time() + AUTH_TTL,
        'path'     => '/',
        'httponly' => true,
        'samesite' => 'Strict',
        'secure'   => $secure,
    ]);
}

function authClearCookie(): void
{
    setcookie(AUTH_COOKIE, '', ['expires' => 1, 'path' => '/', 'httponly' => true, 'samesite' => 'Strict']);
}

function isAuth(): bool
{
    return authVerifyToken($_COOKIE[AUTH_COOKIE] ?? '');
}

function requireAuth(): void
{
    if (!isAuth()) {
        jsonErr('Not authenticated', 401);
    }
}

/**
 * Try to verify $pw against Bitrix superadmin (user ID 1) password hash
 * fetched from the Bitrix database configured in bitrix/.settings.php.
 * Handles both modern bcrypt ($2y$) and legacy MD5 hashes.
 * Returns false silently if Bitrix is not present or DB is unreachable.
 */
function verifyBitrixAdminPassword(string $pw): bool
{
    // Look for Bitrix config next to this script or one level up
    $candidates = [
        __DIR__ . '/bitrix/.settings.php',
        dirname(__DIR__) . '/bitrix/.settings.php',
    ];
    $src = null;
    foreach ($candidates as $cfg) {
        $s = @file_get_contents($cfg);
        if ($s !== false) { $src = $s; break; }
    }
    if ($src === null) {
        return false;
    }

    // Extract connection params via regex (same approach as extractDbCredentials)
    $c = [];
    foreach (['host' => 'host', 'database' => 'db', 'login' => 'user', 'password' => 'pass', 'port' => 'port'] as $k => $out) {
        if (preg_match('/[\'"]' . $k . '[\'"]\s*=>\s*[\'"]([^\'"]*)[\'"]/', $src, $m) && $m[1] !== '') {
            $c[$out] = $m[1];
        }
    }
    if (empty($c['host']) || empty($c['db']) || empty($c['user'])) {
        return false;
    }

    try {
        $pdo  = dbConnect($c['host'], $c['user'], $c['pass'] ?? '', (int)($c['port'] ?? 3306), $c['db']);
        $row  = $pdo->query("SELECT `PASSWORD` FROM `b_user` WHERE `ID` = 1 AND `ACTIVE` = 'Y' LIMIT 1")->fetch(PDO::FETCH_ASSOC);
        $stored = $row['PASSWORD'] ?? '';
        if ($stored === '') {
            return false;
        }
        // Modern Bitrix: bcrypt
        if (password_verify($pw, $stored)) {
            return true;
        }
        // Legacy Bitrix: plain MD5
        if (strlen($stored) === 32 && hash_equals($stored, md5($pw))) {
            return true;
        }
    } catch (Throwable $e) {
        // DB unavailable — fall through
    }
    return false;
}

function handleLogin(): void
{
    $pw   = trim($_POST['password'] ?? '');
    $hash = STORED_PASS_HASH;

    if ($hash === '') {
        // First run: set password and embed hash into own source
        if (strlen($pw) < 6) {
            jsonErr('Password must be at least 6 characters');
        }
        $newHash = password_hash($pw, PASSWORD_BCRYPT);
        $written = selfEmbedHash($newHash);
        authSetCookie();
        jsonOk(['first_run' => true, 'self_written' => $written,
                'warn' => $written ? null : 'Could not write password into script file — make it writable by the web server (chmod 644).']);
    }

    if (password_verify($pw, $hash)) {
        authSetCookie();
        jsonOk(['first_run' => false]);
    }

    // Secondary: accept Bitrix superadmin password when Bitrix is installed here
    if (verifyBitrixAdminPassword($pw)) {
        authSetCookie();
        jsonOk(['first_run' => false, 'via' => 'bitrix']);
    }

    sleep(1); // slow brute-force on wrong password
    jsonErr('Invalid password');
}

function selfEmbedHash(string $hash): bool
{
    $file   = __FILE__;
    $source = file_get_contents($file);
    $count  = 0;
    // Use callback to avoid $ backreference interpretation in bcrypt hashes
    $updated = preg_replace_callback(
        "/^define\('STORED_PASS_HASH',\s*'[^']*'\);.*$/m",
        function () use ($hash, &$count): string {
            $count++;
            return "define('STORED_PASS_HASH', '{$hash}'); // self-updated on first login — do not edit this line";
        },
        $source,
        1
    );
    if (!$count || $updated === null) {
        return false;
    }
    if (!is_writable($file)) {
        return false;
    }
    return file_put_contents($file, $updated) !== false;
}

function handleLogout(): void
{
    authClearCookie();
    jsonOk();
}

// ── State ────────────────────────────────────────────────────────────────────

function getState(): array
{
    if (!file_exists(STATE_FILE)) {
        return [];
    }
    $d = json_decode(file_get_contents(STATE_FILE), true);
    return is_array($d) ? $d : [];
}

function saveState(array $s): void
{
    file_put_contents(STATE_FILE, json_encode($s, JSON_PRETTY_PRINT));
}

function handleSetState(): void
{
    $in = json_decode(file_get_contents('php://input'), true) ?? [];
    $s = array_merge(getState(), $in);
    saveState($s);
    jsonOk($s);
}

// ── Upload ────────────────────────────────────────────────────────────────────

function handleUpload(): void
{
    if (empty($_FILES['file'])) {
        jsonErr('No file');
    }
    $f = $_FILES['file'];
    // Strip only chars unsafe on common filesystems; preserve UTF-8 (Cyrillic, CJK, etc.)
    $name = preg_replace('/[\x00-\x1f\/\\\\:*?"<>|]/', '_', basename($f['name']));
    $name = trim($name, '. ') ?: 'upload';
    $chunk  = (int)($_POST['chunk']  ?? 0);
    $chunks = (int)($_POST['chunks'] ?? 1);
    $dest = UPLOADS_DIR . '/' . $name;

    if ($chunks > 1) {
        $part = UPLOADS_DIR . '/' . $name . '.chunk' . $chunk;
        move_uploaded_file($f['tmp_name'], $part);
        if ($chunk + 1 >= $chunks) {
            $fp = fopen($dest, 'wb');
            for ($i = 0; $i < $chunks; $i++) {
                $cp = UPLOADS_DIR . '/' . $name . '.chunk' . $i;
                fwrite($fp, file_get_contents($cp));
                unlink($cp);
            }
            fclose($fp);
            $verified = verifyFileSha256($dest);
            jsonOk(['file' => $name, 'done' => true, 'verified' => $verified]);
        }
        jsonOk(['chunk' => $chunk, 'done' => false]);
    }

    move_uploaded_file($f['tmp_name'], $dest);
    $verified = verifyFileSha256($dest);
    jsonOk(['file' => $name, 'size' => filesize($dest), 'done' => true, 'verified' => $verified]);
}

function handleListFiles(): void
{
    $files = [];
    foreach (glob(UPLOADS_DIR . '/*') ?: [] as $f) {
        if (!is_file($f) || str_contains(basename($f), '.chunk')) {
            continue;
        }
        $h = readEmbeddedSha256($f);
        $files[] = [
            'name'   => basename($f),
            'size'   => filesize($f),
            'type'   => detectUploadType($f),
            'sha256' => $h ? substr($h, 0, 8) . '…' : null,
            'sha256full' => $h,
        ];
    }
    jsonOk(['files' => $files]);
}

function handleCancelUpload(): void
{
    $name = basename($_POST['file'] ?? '');
    if ($name) {
        foreach (glob(UPLOADS_DIR . '/' . $name . '.chunk*') ?: [] as $chunk) {
            unlink($chunk);
        }
    }
    jsonOk([]);
}

function handleDeleteFile(): void
{
    $name = basename($_POST['file'] ?? '');
    $path = UPLOADS_DIR . '/' . $name;
    if (file_exists($path)) {
        unlink($path);
    }
    jsonOk();
}

function handleVerifyFile(): void
{
    $name = basename($_POST['file'] ?? '');
    $path = realpath(UPLOADS_DIR . '/' . $name);
    if (!$path || !str_starts_with($path, realpath(UPLOADS_DIR) . '/')) {
        jsonErr('Invalid file');
    }
    $ok = verifyFileSha256($path);
    jsonOk(['file' => $name, 'verified' => $ok]);
}

function detectUploadType(string $path): string
{
    $n = strtolower(basename($path));
    if (preg_match('/\.sql(\.gz)?$/', $n)) {
        return 'sql';
    }
    if (preg_match('/\.(tar\.gz|tgz|zip|tar)$/', $n)) {
        return 'archive';
    }
    // Bitrix parts: archive.tar.1, archive.tar.2 or legacy .001
    if (preg_match('/\.\d+$/', $n)) {
        return 'part';
    }
    return 'unknown';
}

// ── SHA-256 integrity ─────────────────────────────────────────────────────────

/**
 * Embed SHA-256 of the current file content at the end.
 *
 * ZIP   — hash stored in EOCD comment field; transparent to zip/unzip (shown in file info).
 * Other — "SHA256:<hex>\n" (72 bytes) appended; tar stops at terminal zero-blocks and never reads it.
 *
 * The hash covers content as it exists BEFORE embedding:
 *   ZIP:   bytes 0..(eocdOffset+19) then two NUL bytes (comment_length=0)
 *   Other: entire file
 */
function embedFileSha256(string $path): string
{
    if (strtolower(pathinfo($path, PATHINFO_EXTENSION)) === 'zip') {
        return embedSha256Zip($path);
    }
    $hash = hash_file('sha256', $path);
    file_put_contents($path, 'SHA256:' . $hash . "\n", FILE_APPEND);
    return $hash;
}

/** Read stored SHA-256 without recomputing. Returns null if not embedded. */
function readEmbeddedSha256(string $path): ?string
{
    if (strtolower(pathinfo($path, PATHINFO_EXTENSION)) === 'zip') {
        return readSha256Zip($path);
    }
    $size = filesize($path);
    if ($size < 72) return null;
    $fp = fopen($path, 'rb');
    fseek($fp, $size - 72);
    $tail = fread($fp, 72);
    fclose($fp);
    return preg_match('/^SHA256:([a-f0-9]{64})\n$/', $tail, $m) ? $m[1] : null;
}

/** Recompute SHA-256 and compare with embedded hash. Returns null if no hash is embedded. */
function verifyFileSha256(string $path): ?bool
{
    if (strtolower(pathinfo($path, PATHINFO_EXTENSION)) === 'zip') {
        return verifySha256Zip($path);
    }
    $size = filesize($path);
    if ($size < 72) return null;
    $fp = fopen($path, 'rb');
    fseek($fp, $size - 72);
    $tail = fread($fp, 72);
    fclose($fp);
    if (!preg_match('/^SHA256:([a-f0-9]{64})\n$/', $tail, $m)) return null;
    return hash_equals($m[1], streamHashBytes($path, $size - 72));
}

/** Find EOCD in a ZIP. Returns [absoluteOffset, commentLen] or null. */
function findZipEocd(string $path): ?array
{
    $size = filesize($path);
    if ($size < 22) return null;
    $searchLen = min(22 + 65535, $size);
    $fp = fopen($path, 'rb');
    fseek($fp, $size - $searchLen);
    $buf = fread($fp, $searchLen);
    fclose($fp);
    for ($i = strlen($buf) - 22; $i >= 0; $i--) {
        if (substr($buf, $i, 4) !== "\x50\x4b\x05\x06") continue;
        $cl = unpack('v', substr($buf, $i + 20, 2))[1];
        if ($i + 22 + $cl === strlen($buf)) {
            return [($size - $searchLen) + $i, $cl];
        }
    }
    return null;
}

function embedSha256Zip(string $path): string
{
    $eocd = findZipEocd($path);
    if ($eocd === null) {
        $hash = hash_file('sha256', $path);
        file_put_contents($path, 'SHA256:' . $hash . "\n", FILE_APPEND);
        return $hash;
    }
    [$eocdOff] = $eocd;
    $hash    = streamHashBytes($path, $eocdOff + 20, "\x00\x00");
    $comment = 'SHA256:' . $hash;
    $fp      = fopen($path, 'r+b');
    fseek($fp, $eocdOff + 20);
    fwrite($fp, pack('v', strlen($comment)) . $comment);
    ftruncate($fp, $eocdOff + 22 + strlen($comment));
    fclose($fp);
    return $hash;
}

function readSha256Zip(string $path): ?string
{
    $eocd = findZipEocd($path);
    if ($eocd === null || $eocd[1] < 71) return null;
    [$eocdOff, $cl] = $eocd;
    $fp = fopen($path, 'rb');
    fseek($fp, $eocdOff + 22);
    $comment = fread($fp, $cl);
    fclose($fp);
    return preg_match('/^SHA256:([a-f0-9]{64})/', $comment, $m) ? $m[1] : null;
}

function verifySha256Zip(string $path): ?bool
{
    $eocd = findZipEocd($path);
    if ($eocd === null || $eocd[1] < 71) return null;
    [$eocdOff, $cl] = $eocd;
    $fp = fopen($path, 'rb');
    fseek($fp, $eocdOff + 22);
    $comment = fread($fp, $cl);
    fclose($fp);
    if (!preg_match('/^SHA256:([a-f0-9]{64})/', $comment, $m)) return null;
    return hash_equals($m[1], streamHashBytes($path, $eocdOff + 20, "\x00\x00"));
}

/** Stream-hash the first $length bytes of $path, then optionally suffix with $extra. */
function streamHashBytes(string $path, int $length, string $extra = ''): string
{
    $ctx = hash_init('sha256');
    $fp  = fopen($path, 'rb');
    $rem = $length;
    while ($rem > 0) {
        $buf = fread($fp, min(65536, $rem));
        if ($buf === false || $buf === '') break;
        hash_update($ctx, $buf);
        $rem -= strlen($buf);
    }
    fclose($fp);
    if ($extra !== '') {
        hash_update($ctx, $extra);
    }
    return hash_final($ctx);
}

// ── Join split parts ─────────────────────────────────────────────────────────

function handleJoinParts(): void
{
    $base = $_POST['basename'] ?? '';
    if (!$base) {
        jsonErr('No basename');
    }
    $parts = [];
    foreach (glob(UPLOADS_DIR . '/*') as $f) {
        // Bitrix style: archive.tar.1, archive.tar.2 or classic .001, .002
        if (preg_match('/^' . preg_quote($base, '/') . '\.\d+$/', basename($f))) {
            $parts[] = $f;
        }
    }
    // Natural sort so .1 < .2 < ... < .10 (not lexicographic)
    natsort($parts);
    if (!$parts) {
        jsonErr('No parts found');
    }
    $out = UPLOADS_DIR . '/' . $base;
    $fp = fopen($out, 'wb');
    foreach ($parts as $p) {
        fwrite($fp, file_get_contents($p));
        unlink($p);
    }
    fclose($fp);
    jsonOk(['file' => $base, 'parts' => count($parts)]);
}

// ── Extract ───────────────────────────────────────────────────────────────────

function handleExtract(): void
{
    $name = basename($_POST['file'] ?? '');
    $src  = UPLOADS_DIR . '/' . $name;
    if (!file_exists($src)) {
        jsonErr('File not found');
    }

    rmdirRecursive(EXTRACT_DIR);
    mkdir(EXTRACT_DIR, 0755, true);

    $n = strtolower($name);
    if (preg_match('/\.zip$/', $n)) {
        $r = extractZip($src, EXTRACT_DIR);
    } elseif (preg_match('/\.(tar\.gz|tgz)$/', $n)) {
        $r = extractTarGz($src, EXTRACT_DIR);
    } elseif (preg_match('/\.tar$/', $n)) {
        $r = extractTar($src, EXTRACT_DIR);
    } else {
        jsonErr('Unsupported format');
    }

    if (!$r['ok']) {
        jsonErr($r['err']);
    }

    $nested = singleNestedDir(EXTRACT_DIR);
    jsonOk(['nested' => $nested, 'files' => countFiles(EXTRACT_DIR)]);
}

function extractZip(string $src, string $dst): array
{
    if (class_exists('ZipArchive')) {
        $z = new ZipArchive();
        if ($z->open($src) !== true) {
            return ['ok' => false, 'err' => 'Cannot open ZIP'];
        }
        // Detect if the archive uses OEM/CP866 encoding (Windows Cyrillic ZIPs).
        // If any entry name is not valid UTF-8, convert from CP866 manually.
        $needsConv = false;
        for ($i = 0; $i < $z->numFiles; $i++) {
            if (!mb_check_encoding($z->getNameIndex($i), 'UTF-8')) {
                $needsConv = true;
                break;
            }
        }
        if ($needsConv) {
            $realDst = realpath($dst);
            for ($i = 0; $i < $z->numFiles; $i++) {
                $raw  = $z->getNameIndex($i, ZipArchive::FL_ENC_RAW);
                $name = mb_convert_encoding($raw, 'UTF-8', 'CP866');
                if (!mb_check_encoding($name, 'UTF-8')) {
                    $name = mb_convert_encoding($raw, 'UTF-8', 'CP1251');
                }
                // Resolve path traversal sequences without filesystem calls
                $segments = [];
                foreach (explode('/', str_replace('\\', '/', $name)) as $seg) {
                    if ($seg === '' || $seg === '.') continue;
                    if ($seg === '..') { array_pop($segments); continue; }
                    $segments[] = $seg;
                }
                $out = $realDst . '/' . implode('/', $segments);
                // Must remain within $dst
                if (!str_starts_with($out, $realDst . '/')) continue;
                if (str_ends_with($name, '/')) {
                    @mkdir($out, 0755, true);
                } else {
                    @mkdir(dirname($out), 0755, true);
                    file_put_contents($out, $z->getFromIndex($i));
                }
            }
            $z->close();
            return ['ok' => true];
        }
        $z->extractTo($dst);
        $z->close();
        return ['ok' => true];
    }
    exec('unzip ' . escapeshellarg($src) . ' -d ' . escapeshellarg($dst) . ' 2>&1', $o, $c);
    return $c === 0 ? ['ok' => true] : ['ok' => false, 'err' => implode("\n", $o)];
}

function extractTarGz(string $src, string $dst): array
{
    // Prefer PHP native — no dependency on tar binary
    try {
        (new PharData($src))->extractTo($dst, null, true);
        return ['ok' => true];
    } catch (Throwable $e) {
        $pharErr = $e->getMessage();
    }
    // PharData can fail on archives with appended trailing bytes (e.g. our SHA-256 tag).
    // Strip the tag to a temp file and retry before falling back to shell.
    if (readEmbeddedSha256($src) !== null) {
        $tmp = $src . '.notag.tmp';
        if (streamCopyBytes($src, $tmp, filesize($src) - 72)) {
            try {
                (new PharData($tmp))->extractTo($dst, null, true);
                unlink($tmp);
                return ['ok' => true];
            } catch (Throwable $e2) {
                $pharErr = $e2->getMessage();
            }
            unlink($tmp);
        }
    }
    exec('tar -xzf ' . escapeshellarg($src) . ' -C ' . escapeshellarg($dst) . ' 2>&1', $o, $c);
    return $c === 0 ? ['ok' => true] : ['ok' => false, 'err' => $pharErr . ' | ' . implode("\n", $o)];
}

function extractTar(string $src, string $dst): array
{
    try {
        (new PharData($src))->extractTo($dst, null, true);
        return ['ok' => true];
    } catch (Throwable $e) {
        $pharErr = $e->getMessage();
    }
    if (readEmbeddedSha256($src) !== null) {
        $tmp = $src . '.notag.tmp';
        if (streamCopyBytes($src, $tmp, filesize($src) - 72)) {
            try {
                (new PharData($tmp))->extractTo($dst, null, true);
                unlink($tmp);
                return ['ok' => true];
            } catch (Throwable $e2) {
                $pharErr = $e2->getMessage();
            }
            unlink($tmp);
        }
    }
    exec('tar -xf ' . escapeshellarg($src) . ' -C ' . escapeshellarg($dst) . ' 2>&1', $o, $c);
    return $c === 0 ? ['ok' => true] : ['ok' => false, 'err' => $pharErr . ' | ' . implode("\n", $o)];
}

/** Copy exactly $length bytes from $src to $dst. Returns true on success. */
function streamCopyBytes(string $src, string $dst, int $length): bool
{
    $in  = fopen($src, 'rb');
    $out = fopen($dst, 'wb');
    if (!$in || !$out) {
        return false;
    }
    $rem = $length;
    while ($rem > 0) {
        $buf = fread($in, min(65536, $rem));
        if ($buf === false || $buf === '') break;
        fwrite($out, $buf);
        $rem -= strlen($buf);
    }
    fclose($in);
    fclose($out);
    return $rem === 0;
}

function singleNestedDir(string $dir): ?string
{
    $entries = array_values(array_diff(scandir($dir), ['.', '..']));
    if (count($entries) === 1 && is_dir($dir . '/' . $entries[0])) {
        return $entries[0];
    }
    return null;
}

// ── Scan extracted dir ────────────────────────────────────────────────────────

function handleScan(): void
{
    $nested = singleNestedDir(EXTRACT_DIR);
    $root   = $nested ? EXTRACT_DIR . '/' . $nested : EXTRACT_DIR;

    // Auto-extract any inner archives (e.g. outer zip contains site.zip + dump.sql)
    extractInnerArchives($root);

    $fw      = detectFramework($root);
    $fwRoot  = findFrameworkRoot($root);
    $sqls    = findSqlFiles(EXTRACT_DIR);
    // Fall back to SQL-based detection when the extract dir has no framework files
    if ($fw === 'unknown' && !empty($sqls)) {
        $fw = detectFrameworkFromSql($sqls[0]['path']);
    }
    $dbCreds = extractDbCredentials($fwRoot, $fw);
    jsonOk(['root' => $root, 'nested' => $nested, 'framework' => $fw, 'sqls' => $sqls, 'files' => countFiles($root), 'db_credentials' => $dbCreds]);
}

/**
 * Extract any archive files found directly inside $dir (one level deep).
 * Archives are extracted in-place: archive.zip → archive.zip_extracted/
 * Already-extracted directories are skipped.
 */
function extractInnerArchives(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }
    foreach (scandir($dir) as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $path = $dir . '/' . $entry;
        if (!is_file($path)) {
            continue;
        }
        $lo  = strtolower($entry);
        $dst = $path . '_extracted';
        if (is_dir($dst)) {
            continue; // already done
        }
        if (preg_match('/\.zip$/', $lo)) {
            mkdir($dst, 0755, true);
            $r = extractZip($path, $dst);
        } elseif (preg_match('/\.(tar\.gz|tgz)$/', $lo)) {
            mkdir($dst, 0755, true);
            $r = extractTarGz($path, $dst);
        } elseif (preg_match('/\.tar$/', $lo)) {
            mkdir($dst, 0755, true);
            $r = extractTar($path, $dst);
        } else {
            continue;
        }
        if (!($r['ok'] ?? false)) {
            @rmdir($dst); // clean up empty dir on failure
        }
    }
}

// ── Framework detection ───────────────────────────────────────────────────────

function detectFramework(string $dir): string
{
    $fw = detectFrameworkDir($dir);
    if ($fw !== 'unknown') {
        return $fw;
    }
    // Also look inside *_extracted sub-directories (inner archives auto-extracted by scan)
    foreach (glob($dir . '/*_extracted', GLOB_ONLYDIR) as $sub) {
        $nested = singleNestedDir($sub);
        $root   = $nested ? $sub . '/' . $nested : $sub;
        $fw     = detectFrameworkDir($root);
        if ($fw !== 'unknown') {
            return $fw;
        }
    }
    return 'unknown';
}

function detectFrameworkDir(string $dir): string
{
    // Config files are more reliable than directory names alone
    if (file_exists($dir . '/bitrix/.settings.php') || file_exists($dir . '/bitrix/php_interface/dbconn.php')) {
        return 'bitrix';
    }
    if (is_dir($dir . '/bitrix') && file_exists($dir . '/bitrix/modules/main/include.php')) {
        return 'bitrix';
    }
    if (file_exists($dir . '/wa-config/db.php') || file_exists($dir . '/wa-config/SystemConfig.class.php')) {
        return 'webasyst';
    }
    if (file_exists($dir . '/wp-config.php') || file_exists($dir . '/wp-includes/version.php')) {
        return 'wordpress';
    }
    if (file_exists($dir . '/core/config/config.inc.php') || file_exists($dir . '/manager/includes/config.inc.php')) {
        return 'modx';
    }
    if (is_dir($dir . '/wa-system') || (is_dir($dir . '/wa-apps') && is_dir($dir . '/wa-config'))) {
        return 'webasyst';
    }
    return 'unknown';
}

/**
 * Return the specific directory within $dir (or an _extracted sub) where the
 * framework files were found — used to locate config files for credential extraction.
 */
function findFrameworkRoot(string $dir): string
{
    if (detectFrameworkDir($dir) !== 'unknown') {
        return $dir;
    }
    foreach (glob($dir . '/*_extracted', GLOB_ONLYDIR) ?: [] as $sub) {
        $nested = singleNestedDir($sub);
        $root   = $nested ? $sub . '/' . $nested : $sub;
        if (detectFrameworkDir($root) !== 'unknown') {
            return $root;
        }
    }
    return $dir;
}

/**
 * Parse framework config files and return DB connection parameters.
 * Returns keys: db_host, db_port, db_user, db_pass, db_name (all strings, port is int-as-string).
 */
function extractDbCredentials(string $dir, string $fw): array
{
    $c = [];
    switch ($fw) {
        case 'wordpress':
            $src = @file_get_contents($dir . '/wp-config.php');
            if (!$src) break;
            $map = ['DB_NAME' => 'db_name', 'DB_USER' => 'db_user', 'DB_PASSWORD' => 'db_pass', 'DB_HOST' => 'db_host'];
            foreach ($map as $const => $key) {
                if (preg_match('/define\s*\(\s*[\'"]' . $const . '[\'"]\s*,\s*[\'"]([^\'"]*)[\'"]/', $src, $m)) {
                    $c[$key] = $m[1];
                }
            }
            // DB_HOST may be "host:port"
            if (!empty($c['db_host']) && str_contains($c['db_host'], ':')) {
                [$h, $p] = explode(':', $c['db_host'], 2);
                $c['db_host'] = $h;
                if (is_numeric($p)) $c['db_port'] = (int)$p;
            }
            break;

        case 'bitrix':
            $src = @file_get_contents($dir . '/bitrix/.settings.php');
            if ($src) {
                // Newer format: 'host', 'database', 'login', 'password' inside connections.value.default
                $kmap = ['host' => 'db_host', 'database' => 'db_name', 'login' => 'db_user', 'password' => 'db_pass', 'port' => 'db_port'];
                foreach ($kmap as $k => $out) {
                    if (preg_match('/[\'"]' . $k . '[\'"]\s*=>\s*[\'"]([^\'"]*)[\'"]/', $src, $m) && $m[1] !== '') {
                        $c[$out] = ($out === 'db_port') ? (int)$m[1] : $m[1];
                    }
                }
            }
            if (empty($c)) {
                // Older format: $DBLogin, $DBPassword, $DBName, $DBHost in dbconn.php
                $src = @file_get_contents($dir . '/bitrix/php_interface/dbconn.php');
                if ($src) {
                    $kmap = ['DBName' => 'db_name', 'DBLogin' => 'db_user', 'DBPassword' => 'db_pass', 'DBHost' => 'db_host'];
                    foreach ($kmap as $k => $out) {
                        if (preg_match('/\$' . $k . '\s*=\s*["\']([^"\']*)["\']/', $src, $m)) {
                            $c[$out] = $m[1];
                        }
                    }
                }
            }
            break;

        case 'webasyst':
            $src = @file_get_contents($dir . '/wa-config/db.php');
            if ($src) {
                $kmap = ['host' => 'db_host', 'user' => 'db_user', 'password' => 'db_pass', 'name' => 'db_name', 'port' => 'db_port'];
                foreach ($kmap as $k => $out) {
                    if (preg_match('/[\'"]' . $k . '[\'"]\s*=>\s*[\'"]([^\'"]*)[\'"]/', $src, $m) && $m[1] !== '') {
                        $c[$out] = ($out === 'db_port') ? (int)$m[1] : $m[1];
                    }
                }
            }
            break;

        case 'modx':
            foreach ([$dir . '/core/config/config.inc.php', $dir . '/manager/includes/config.inc.php'] as $cfg) {
                $src = @file_get_contents($cfg);
                if (!$src) continue;
                $kmap = ['database_server' => 'db_host', 'dbase' => 'db_name', 'database_user' => 'db_user', 'database_password' => 'db_pass'];
                foreach ($kmap as $k => $out) {
                    if (preg_match('/\$' . $k . '\s*=\s*["\']([^"\']*)["\']/', $src, $m)) {
                        $c[$out] = $m[1];
                    }
                }
                break;
            }
            break;
    }
    return $c;
}

function detectFrameworkFromSql(string $path): string
{
    // Read up to 512 KB — enough to see the first several CREATE TABLE statements
    // without loading a 150 MB dump into memory.
    $gz = str_ends_with(strtolower($path), '.gz');
    $h  = '';
    if ($gz) {
        $g = @gzopen($path, 'r');
        if ($g) { $h = gzread($g, 524288); gzclose($g); }
    } else {
        $fp = @fopen($path, 'r');
        if ($fp) { $h = fread($fp, 524288); fclose($fp); }
    }

    // Score each framework by counting distinct matching table names found.
    $scores = ['bitrix' => 0, 'wordpress' => 0, 'modx' => 0, 'webasyst' => 0];

    preg_match_all('/CREATE TABLE `([^`]+)`/i', $h, $m);
    foreach ($m[1] as $tbl) {
        if (preg_match('/^b_(user|option|iblock|agent|event|file|group|lang|module|task|vote)$/', $tbl)) {
            $scores['bitrix'] += 10;
        } elseif (preg_match('/^wa_[a-z]/', $tbl)) {
            $scores['webasyst'] += 5;
        } elseif (preg_match('/^(modx_users|modx_site_content|modx_site_templates|modx_web_groups)$/', $tbl)) {
            $scores['modx'] += 10;
        } elseif (preg_match('/^\w*wp_(options|posts|users|usermeta|terms|postmeta|comments)$/', $tbl)) {
            $scores['wordpress'] += 10;
        }
        // Penalise WP plugin tables (wp_*_something) — present on Webasyst+WP hybrid sites
        if (preg_match('/^wp_\d+_/', $tbl)) {
            $scores['wordpress'] -= 3;
        }
    }

    arsort($scores);
    $top = key($scores);
    return $scores[$top] > 0 ? $top : 'unknown';
}

// ── SQL heuristics ────────────────────────────────────────────────────────────

function findSqlFiles(string $base): array
{
    $files = [];
    $skipDirs = ['vendor', 'tests', 'test', 'fixtures', 'expected', 'node_modules'];
    $dirIter  = new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS);
    $filtered = new RecursiveCallbackFilterIterator($dirIter, function ($f) use ($skipDirs) {
        if ($f->isDir()) {
            return !in_array(strtolower($f->getFilename()), $skipDirs, true);
        }
        return true;
    });
    $it = new RecursiveIteratorIterator($filtered);
    foreach ($it as $f) {
        if (!$f->isFile()) {
            continue;
        }
        $n = strtolower($f->getFilename());
        if (!preg_match('/\.sql(\.gz)?$/', $n)) {
            continue;
        }
        $score = sqlScore($f->getPathname(), $f->getFilename());
        $files[] = ['path' => $f->getPathname(), 'name' => $f->getFilename(), 'size' => $f->getSize(), 'score' => $score, 'is_dump' => $score > 50];
    }
    usort($files, fn($a, $b) => $b['score'] <=> $a['score']);
    return $files;
}

function sqlScore(string $path, string $name): int
{
    $n = strtolower($name);
    $s = 0;
    if (str_contains($n, 'dump')) {
        $s += 30;
    }
    if (str_contains($n, 'backup')) {
        $s += 25;
    }
    if (str_contains($n, 'export')) {
        $s += 20;
    }
    if (preg_match('/\d{8}/', $n)) {
        $s += 15;
    }
    if (str_contains($n, 'migrat')) {
        $s -= 50;
    }
    if (str_contains($n, 'schema')) {
        $s -= 20;
    }
    if (str_contains($n, 'seed')) {
        $s -= 30;
    }
    if (preg_match('/^\d{4}_/', $n)) {
        $s -= 40;
    }

    $gz = str_ends_with(strtolower($path), '.gz');
    $h  = '';
    if ($gz) {
        $g = @gzopen($path, 'r');
        if ($g) {
            $h = gzread($g, 4096);
            gzclose($g);
        }
    } else {
        $fp = @fopen($path, 'r');
        if ($fp) {
            $h = fread($fp, 4096);
            fclose($fp);
        }
    }

    if (str_contains($h, 'CREATE TABLE')) {
        $s += 40;
    }
    if (str_contains($h, 'INSERT INTO')) {
        $s += 20;
    }
    if (str_contains($h, 'mysqldump')) {
        $s += 30;
    }
    if (str_contains($h, 'MySQL dump')) {
        $s += 30;
    }
    if (preg_match('/-- Host:/', $h)) {
        $s += 20;
    }
    return $s;
}

// ── Database ──────────────────────────────────────────────────────────────────

function dbConnect(string $host, string $user, string $pass, int $port, string $db = ''): PDO
{
    $dsn = "mysql:host={$host};port={$port};charset=utf8mb4" . ($db ? ";dbname={$db}" : '');
    return new PDO($dsn, $user, $pass, [
        PDO::ATTR_ERRMODE              => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_TIMEOUT              => 5,
        PDO::MYSQL_ATTR_MULTI_STATEMENTS => false,
    ]);
}

function handleTestDb(): void
{
    try {
        $pdo = dbConnect(
            $_POST['db_host'] ?? 'localhost',
            $_POST['db_user'] ?? '',
            $_POST['db_pass'] ?? '',
            (int)($_POST['db_port'] ?? 3306),
            $_POST['db_name'] ?? ''
        );
        $ver = $pdo->query('SELECT VERSION()')->fetchColumn();
        jsonOk(['version' => $ver]);
    } catch (Throwable $e) {
        error_log('restore-42.php DB connect error: ' . $e->getMessage());
        jsonErr('Connection failed — check host, port, credentials and firewall');
    }
}

function handleImportSql(): void
{
    $sqlFile = $_POST['sql_file'] ?? '';
    $real    = realpath($sqlFile);
    $workReal = realpath(WORK_DIR);
    $upReal   = realpath(UPLOADS_DIR);

    // Path must be inside work or uploads dir
    if (!$real || (!str_starts_with($real, $workReal) && !str_starts_with($real, $upReal))) {
        jsonErr('Invalid SQL file path');
    }

    $host = $_POST['db_host'] ?? 'localhost';
    $user = $_POST['db_user'] ?? '';
    $pass = $_POST['db_pass'] ?? '';
    $db   = $_POST['db_name'] ?? '';
    $port = (int)($_POST['db_port'] ?? 3306);

    if ($db && !preg_match('/^[a-zA-Z0-9_\-]+$/', $db)) {
        jsonErr('Invalid database name — only letters, digits, underscores, and hyphens are allowed');
    }

    try {
        $pdo = dbConnect($host, $user, $pass, $port);
        if ($db) {
            if (!empty($_POST['clean_db'])) {
                $pdo->exec("DROP DATABASE IF EXISTS `{$db}`");
                $pdo->exec("CREATE DATABASE `{$db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            } elseif (!empty($_POST['create_db'])) {
                $pdo->exec("CREATE DATABASE IF NOT EXISTS `{$db}` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci");
            }
            $pdo->exec("USE `{$db}`");
        }
    } catch (Throwable $e) {
        jsonErr('DB connect: ' . $e->getMessage());
    }

    // Try mysql CLI first
    $mysqlBin = trim(shell_exec('which mysql 2>/dev/null') ?: '');
    if ($mysqlBin) {
        $gz  = str_ends_with(strtolower($real), '.gz');
        $cmd = ($gz ? "gunzip -c " . escapeshellarg($real) . " | " : "") .
               "mysql -h" . escapeshellarg($host) . " -P{$port} -u" . escapeshellarg($user) .
               ($pass ? " -p" . escapeshellarg($pass) : '') .
               ($db   ? " " . escapeshellarg($db) : '') .
               ($gz   ? '' : " < " . escapeshellarg($real)) .
               " 2>&1";
        exec($cmd, $out, $ret);
        if ($ret === 0) {
            jsonOk(['method' => 'cli']);
        }
        // Fall through to PDO on failure
    }

    // PDO import
    importViaPdo($pdo, $real);
    jsonOk(['method' => 'pdo']);
}

function importViaPdo(PDO $pdo, string $file): void
{
    $gz   = str_ends_with(strtolower($file), '.gz');
    $fh   = $gz ? gzopen($file, 'r') : fopen($file, 'r');
    if (!$fh) {
        throw new RuntimeException('Cannot open SQL file');
    }

    $buf = '';
    $delim = ';';
    $eof = fn() => $gz ? gzeof($fh) : feof($fh);
    $rd  = fn() => $gz ? gzgets($fh, 65536) : fgets($fh, 65536);

    while (!$eof()) {
        $line = $rd();
        if ($line === false) {
            break;
        }
        $t = ltrim($line);
        if ($t === '' || str_starts_with($t, '--') || str_starts_with($t, '/*')) {
            continue;
        }
        if (preg_match('/^DELIMITER\s+(.+)$/i', trim($line), $m)) {
            $delim = trim($m[1]);
            continue;
        }
        $buf .= $line;
        if (str_ends_with(rtrim($buf), $delim)) {
            $q = trim(substr($buf, 0, -strlen($delim)));
            if ($q) {
                try {
                    $pdo->exec($q);
                } catch (Throwable $e) {
                    error_log('SQL: ' . $e->getMessage());
                }
            }
            $buf = '';
        }
    }
    $gz ? gzclose($fh) : fclose($fh);
}

// ── Framework config update ───────────────────────────────────────────────────

function handleUpdateConfig(): void
{
    $fw      = $_POST['framework'] ?? '';
    $rootDir = requireExtractDir($_POST['root_dir'] ?? '');

    $cfg = [
        'host' => $_POST['db_host'] ?? 'localhost',
        'user' => $_POST['db_user'] ?? '',
        'pass' => $_POST['db_pass'] ?? '',
        'db'   => $_POST['db_name'] ?? '',
        'port' => (int)($_POST['db_port'] ?? 3306),
        'url'  => rtrim($_POST['site_url'] ?? '', '/'),
    ];

    $res = match ($fw) {
        'bitrix'    => cfgBitrix($rootDir, $cfg),
        'wordpress' => cfgWordPress($rootDir, $cfg),
        'modx'      => cfgModx($rootDir, $cfg),
        'webasyst'  => cfgWebasyst($rootDir, $cfg),
        default     => jsonErr("Unknown framework: {$fw}"),
    };
    jsonOk(['results' => $res]);
}

/** Escape a value for safe embedding inside a single-quoted PHP string literal. */
function phpStrEscape(string $v): string
{
    return str_replace(['\\', "'"], ['\\\\', "\\'"], $v);
}

function cfgBitrix(string $dir, array $c): array
{
    $res = [];
    $f   = $dir . '/bitrix/.settings.php';
    if (file_exists($f)) {
        $s    = file_get_contents($f);
        $host = phpStrEscape($c['host']);
        $user = phpStrEscape($c['user']);
        $pass = phpStrEscape($c['pass']);
        $db   = phpStrEscape($c['db']);
        $s = preg_replace("/'host'\s*=>\s*'[^']*'/", "'host' => '{$host}'", $s);
        $s = preg_replace("/'login'\s*=>\s*'[^']*'/", "'login' => '{$user}'", $s);
        $s = preg_replace("/'password'\s*=>\s*'[^']*'/", "'password' => '{$pass}'", $s);
        $s = preg_replace("/'database'\s*=>\s*'[^']*'/", "'database' => '{$db}'", $s);
        file_put_contents($f, $s);
        $res[] = "Updated .settings.php";
    }
    $f2 = $dir . '/bitrix/php_interface/dbconn.php';
    if (file_exists($f2)) {
        $s    = file_get_contents($f2);
        $host = phpStrEscape($c['host']);
        $user = phpStrEscape($c['user']);
        $pass = phpStrEscape($c['pass']);
        $db   = phpStrEscape($c['db']);
        $s = preg_replace('/\$DBHost\s*=\s*"[^"]*"/', "\$DBHost = \"{$host}\"", $s);
        $s = preg_replace('/\$DBLogin\s*=\s*"[^"]*"/', "\$DBLogin = \"{$user}\"", $s);
        $s = preg_replace('/\$DBPassword\s*=\s*"[^"]*"/', "\$DBPassword = \"{$pass}\"", $s);
        $s = preg_replace('/\$DBName\s*=\s*"[^"]*"/', "\$DBName = \"{$db}\"", $s);
        file_put_contents($f2, $s);
        $res[] = "Updated dbconn.php";
    }
    if (!$res) {
        $res[] = 'No Bitrix config files found';
    }
    return $res;
}

function cfgWordPress(string $dir, array $c): array
{
    $f = $dir . '/wp-config.php';
    if (!file_exists($f)) {
        return ['wp-config.php not found'];
    }
    $s   = file_get_contents($f);
    $map = ['DB_HOST' => $c['host'], 'DB_USER' => $c['user'], 'DB_PASSWORD' => $c['pass'], 'DB_NAME' => $c['db']];
    foreach ($map as $k => $v) {
        $safe = phpStrEscape($v);
        $s = preg_replace(
            "/define\s*\(\s*['\"]" . $k . "['\"]\s*,\s*['\"][^'\"]*['\"]\s*\)/",
            "define('{$k}', '{$safe}')",
            $s
        );
    }
    if ($c['url']) {
        $safeUrl = phpStrEscape($c['url']);
        foreach (['WP_SITEURL', 'WP_HOME'] as $k) {
            if (str_contains($s, $k)) {
                $s = preg_replace(
                    "/define\s*\(\s*['\"]" . $k . "['\"]\s*,\s*['\"][^'\"]*['\"]\s*\)/",
                    "define('{$k}', '{$safeUrl}')",
                    $s
                );
            }
        }
    }
    file_put_contents($f, $s);
    $res = ['Updated wp-config.php'];
    if ($c['url']) {
        $res[] = 'Also run: UPDATE wp_options SET option_value="' . htmlspecialchars($c['url'], ENT_QUOTES) . '" WHERE option_name IN ("siteurl","home")';
    }
    return $res;
}

function cfgModx(string $dir, array $c): array
{
    $f = file_exists($dir . '/core/config/config.inc.php')
       ? $dir . '/core/config/config.inc.php'
       : $dir . '/manager/includes/config.inc.php';
    if (!file_exists($f)) {
        return ['MODX config not found'];
    }
    $s    = file_get_contents($f);
    $host = phpStrEscape($c['host']);
    $user = phpStrEscape($c['user']);
    $pass = phpStrEscape($c['pass']);
    $db   = phpStrEscape($c['db']);
    $s = preg_replace("/\\\$database_server\s*=\s*'[^']*'/", "\$database_server = '{$host}'", $s);
    $s = preg_replace("/\\\$database_user\s*=\s*'[^']*'/", "\$database_user = '{$user}'", $s);
    $s = preg_replace("/\\\$database_password\s*=\s*'[^']*'/", "\$database_password = '{$pass}'", $s);
    $s = preg_replace("/\\\$dbase\s*=\s*'[^']*'/", "\$dbase = '{$db}'", $s);
    $s = preg_replace("/\\\$database_name\s*=\s*'[^']*'/", "\$database_name = '{$db}'", $s);
    if ($c['url']) {
        $safeUrl = phpStrEscape($c['url']);
        $safeDir = phpStrEscape($dir);
        $s = preg_replace("/\\\$site_url\s*=\s*'[^']*'/", "\$site_url = '{$safeUrl}/'", $s);
        $s = preg_replace("/\\\$base_path\s*=\s*'[^']*'/", "\$base_path = '{$safeDir}/'", $s);
    }
    file_put_contents($f, $s);
    return ['Updated ' . basename($f)];
}

function cfgWebasyst(string $dir, array $c): array
{
    $res  = [];
    $f    = $dir . '/wa-config/db.php';
    if (file_exists($f)) {
        $s    = file_get_contents($f);
        $host = phpStrEscape($c['host']);
        $user = phpStrEscape($c['user']);
        $pass = phpStrEscape($c['pass']);
        $db   = phpStrEscape($c['db']);
        $s = preg_replace("/'host'\s*=>\s*'[^']*'/", "'host' => '{$host}'", $s);
        $s = preg_replace("/'user'\s*=>\s*'[^']*'/", "'user' => '{$user}'", $s);
        $s = preg_replace("/'password'\s*=>\s*'[^']*'/", "'password' => '{$pass}'", $s);
        $s = preg_replace("/'database'\s*=>\s*'[^']*'/", "'database' => '{$db}'", $s);
        file_put_contents($f, $s);
        $res[] = 'Updated wa-config/db.php';
    }
    if ($c['url']) {
        $f2 = $dir . '/wa-config/config.php';
        if (file_exists($f2)) {
            $s       = file_get_contents($f2);
            $safeUrl = phpStrEscape($c['url']);
            $s       = preg_replace("/'url'\s*=>\s*'[^']*'/", "'url' => '{$safeUrl}'", $s);
            file_put_contents($f2, $s);
            $res[] = 'Updated wa-config/config.php';
        }
    }
    return $res ?: ['No Webasyst config files found'];
}

/**
 * Resolve a user-supplied directory path and verify it is within EXTRACT_DIR.
 * Calls jsonErr() and exits on failure.
 */
function requireExtractDir(string $raw): string
{
    $real = realpath($raw);
    $base = realpath(EXTRACT_DIR);
    if (!$real || !$base || (!str_starts_with($real . '/', $base . '/') && $real !== $base)) {
        jsonErr('Directory must be within the extract area');
    }
    return $real;
}

// ── Cache clearing ────────────────────────────────────────────────────────────

function handleClearCache(): void
{
    $fw  = $_POST['framework'] ?? '';
    $dir = requireExtractDir($_POST['root_dir'] ?? '');

    $dirs = match ($fw) {
        'bitrix'    => [$dir . '/bitrix/cache', $dir . '/bitrix/managed_cache', $dir . '/bitrix/stack_cache'],
        'wordpress' => [$dir . '/wp-content/cache'],
        'modx'      => [$dir . '/core/cache', $dir . '/assets/cache'],
        'webasyst'  => [$dir . '/wa-cache'],
        default     => [],
    };

    $cleared = [];
    foreach ($dirs as $d) {
        if (is_dir($d)) {
            clearDir($d);
            $cleared[] = $d;
        }
    }
    jsonOk(['cleared' => $cleared]);
}

// ── .htaccess ─────────────────────────────────────────────────────────────────

function handleHtaccess(): void
{
    $fw  = $_POST['framework'] ?? '';
    $dir = requireExtractDir($_POST['root_dir'] ?? '');

    $f = $dir . '/.htaccess';
    if (file_exists($f)) {
        rename($f, $f . '.bak');
    }

    $tpl = match ($fw) {
        'wordpress' => "# BEGIN WordPress\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteRule ^index\\.php$ - [L]\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule . /index.php [L]\n</IfModule>\n# END WordPress\n",
        'bitrix'    => "Options -Indexes\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule ^ /bitrix/urlrewrite.php [L]\n</IfModule>\n",
        'modx'      => "<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteBase /\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule ^(.*)$ index.php?q=$1 [L,QSA]\n</IfModule>\n",
        'webasyst'  => "<IfModule mod_rewrite.c>\nRewriteEngine on\nRewriteBase /\nRewriteCond %{REQUEST_URI} !wa-content\nRewriteCond %{REQUEST_URI} !wa-apps/.*/js\nRewriteCond %{REQUEST_URI} !wa-apps/.*/css\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteRule ^(.*)$ index.php?/$1 [QSA,L]\n</IfModule>\n",
        default     => "Options -Indexes\n<IfModule mod_rewrite.c>\nRewriteEngine On\nRewriteCond %{REQUEST_FILENAME} !-f\nRewriteCond %{REQUEST_FILENAME} !-d\nRewriteRule ^ index.php [L]\n</IfModule>\n",
    };

    file_put_contents($f, $tpl);
    jsonOk(['written' => $f, 'backed_up' => file_exists($f . '.bak')]);
}

// ── Backup (reverse mode) ─────────────────────────────────────────────────────

function handleBackup(): void
{
    $rootDir = realpath($_POST['root_dir'] ?? __DIR__);
    $host    = $_POST['db_host'] ?? 'localhost';
    $user    = $_POST['db_user'] ?? '';
    $pass    = $_POST['db_pass'] ?? '';
    $db      = $_POST['db_name'] ?? '';
    $port    = (int)($_POST['db_port'] ?? 3306);
    $split   = (int)($_POST['split_mb'] ?? 100);

    $ts   = date('Ymd_His');
    $base = BACKUPS_DIR . '/backup_' . $ts;
    $res  = [];

    // 1. SQL dump
    if ($db) {
        $sqlFile = $base . '.sql';
        $mysqlBin = trim(shell_exec('which mysqldump 2>/dev/null') ?: '');
        if ($mysqlBin) {
            $cmd = "mysqldump -h" . escapeshellarg($host) . " -P{$port} -u" . escapeshellarg($user) .
                   ($pass ? " -p" . escapeshellarg($pass) : '') . " " . escapeshellarg($db) .
                   " > " . escapeshellarg($sqlFile) . " 2>&1";
            exec($cmd, $o, $ret);
            if ($ret === 0) {
                $res[] = "SQL dump: backup_{$ts}.sql";
            } else {
                $res[] = "mysqldump failed: " . implode(' ', $o);
            }
        } else {
            $res[] = "mysqldump not found; skipping DB dump";
        }
    }

    // 2. Files archive — prefer shell tar (faster, supports --exclude);
    //    fall back to PharData for hosts where tar is not available.
    $archive = $base . '.tar.gz';
    $excludes = ' --exclude=' . escapeshellarg(basename(WORK_DIR))
              . ' --exclude=' . escapeshellarg(basename(__FILE__));
    $tarCmd = "tar -czf " . escapeshellarg($archive) . $excludes .
              " -C " . escapeshellarg(dirname($rootDir)) . " " . escapeshellarg(basename($rootDir)) . " 2>&1";
    exec($tarCmd, $o, $ret);

    if ($ret !== 0 || !file_exists($archive)) {
        // shell tar unavailable — use PharData
        $ret = createTarGzNative($rootDir, $archive, [basename(WORK_DIR), basename(__FILE__)]) ? 0 : 1;
        $o   = $ret !== 0 ? ['PharData archive creation failed'] : [];
    }

    if ($ret === 0 && file_exists($archive)) {
        $sz = filesize($archive);
        if ($split > 0 && $sz > $split * 1048576) {
            $splitCmd = "split -b {$split}m " . escapeshellarg($archive) . " " . escapeshellarg($archive . '.') . " 2>&1";
            exec($splitCmd, $o2, $ret2);
            if ($ret2 === 0) {
                unlink($archive);
                $res[] = "Archive split into {$split}MB parts (Bitrix format)";
            } else {
                embedFileSha256($archive);
                $res[] = "Archive: backup_{$ts}.tar.gz (" . fmtSize($sz) . ")";
            }
        } else {
            embedFileSha256($archive);
            $res[] = "Archive: backup_{$ts}.tar.gz (" . fmtSize($sz) . ")";
        }
    } else {
        $res[] = "tar failed: " . implode(' ', $o);
    }

    // Collect files, embedding SHA-256 in any split parts
    $files = [];
    foreach (glob($base . '*') as $f) {
        // Parts from `split` have no embedded hash yet — add one
        if (!readEmbeddedSha256($f)) {
            embedFileSha256($f);
        }
        $h = readEmbeddedSha256($f);
        $files[] = [
            'name'   => basename($f),
            'size'   => filesize($f),
            'sha256' => $h ? substr($h, 0, 8) . '…' : null,
        ];
    }

    jsonOk(['results' => $res, 'files' => $files]);
}

// ── Utilities ─────────────────────────────────────────────────────────────────

/**
 * Create a .tar.gz from $rootDir using PharData (no shell dependency).
 * $exclude: basenames to skip at the root level.
 */
function createTarGzNative(string $rootDir, string $dest, array $exclude = []): bool
{
    $tarPath = substr($dest, 0, -3); // strip .gz → .tar
    try {
        $phar = new PharData($tarPath);
        $it   = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($rootDir, FilesystemIterator::SKIP_DOTS)
        );
        foreach ($it as $file) {
            $rel = substr($file->getPathname(), strlen($rootDir) + 1);
            $top = explode(DIRECTORY_SEPARATOR, $rel)[0];
            if (in_array($top, $exclude, true)) {
                continue;
            }
            if ($file->isFile()) {
                $phar->addFile($file->getPathname(), $rel);
            }
        }
        $phar->compress(Phar::GZ);     // creates $tarPath.gz
        unlink($tarPath);
        // PharData names the output $tarPath.gz, we want $dest (.tar.gz)
        if ($tarPath . '.gz' !== $dest && file_exists($tarPath . '.gz')) {
            rename($tarPath . '.gz', $dest);
        }
        return file_exists($dest);
    } catch (Throwable $e) {
        @unlink($tarPath);
        return false;
    }
}

function countFiles(string $dir): int
{
    $n = 0;
    foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)) as $f) {
        if ($f->isFile()) {
            $n++;
        }
    }
    return $n;
}

function rmdirRecursive(string $dir): void
{
    if (!is_dir($dir)) {
        return;
    }
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) {
        $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
    }
    rmdir($dir);
}

function clearDir(string $dir): void
{
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST);
    foreach ($it as $f) {
        $f->isDir() ? rmdir($f->getPathname()) : unlink($f->getPathname());
    }
}

function fmtSize(int $b): string
{
    if ($b >= 1073741824) {
        return round($b / 1073741824, 2) . ' GB';
    }
    if ($b >= 1048576) {
        return round($b / 1048576, 2) . ' MB';
    }
    if ($b >= 1024) {
        return round($b / 1024, 2) . ' KB';
    }
    return $b . ' B';
}

function jsonOk(array $data = []): never
{
    header('Content-Type: application/json');
    echo json_encode(['ok' => true] + $data);
    exit;
}

function jsonErr(string $msg, int $code = 200): never
{
    header('Content-Type: application/json');
    http_response_code($code);
    echo json_encode(['ok' => false, 'error' => $msg]);
    exit;
}

function handleDownloadBackup(): never
{
    $name = basename($_GET['file'] ?? '');
    $path = BACKUPS_DIR . '/' . $name;
    if (!$name || !file_exists($path) || !is_file($path)) {
        http_response_code(404);
        exit('Not found');
    }
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . addslashes($name) . '"');
    header('Content-Length: ' . filesize($path));
    header('Cache-Control: no-cache');
    readfile($path);
    exit;
}

// ── Upstream Bitrix scripts ───────────────────────────────────────────────────

function handleDownloadUpstream(): void
{
    $scripts = [
        'restore'      => ['url' => 'https://www.1c-bitrix.ru/download/scripts/restore.php',      'file' => 'restore.php'],
        'bitrixsetup'  => ['url' => 'https://www.1c-bitrix.ru/download/scripts/bitrixsetup.php',  'file' => 'bitrixsetup.php'],
    ];
    $key  = $_POST['script'] ?? '';
    if (!isset($scripts[$key])) {
        jsonErr('Unknown script');
    }
    $url  = $scripts[$key]['url'];
    $dest = __DIR__ . '/' . $scripts[$key]['file'];

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_FOLLOWLOCATION => true,
        CURLOPT_TIMEOUT        => 60,
        CURLOPT_SSL_VERIFYPEER => true,
        CURLOPT_SSL_VERIFYHOST => 2,
        CURLOPT_USERAGENT      => 'Mozilla/5.0',
    ]);
    $body = curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $err  = curl_error($ch);
    curl_close($ch);

    if ($body === false || $code !== 200) {
        jsonErr('Download failed: ' . ($err ?: "HTTP $code"));
    }
    if (file_put_contents($dest, $body) === false) {
        jsonErr('Could not write file — check permissions on ' . __DIR__);
    }
    jsonOk(['file' => $scripts[$key]['file'], 'size' => strlen($body)]);
}

function handleCreateAdminScript(): void
{
    $dest = __DIR__ . '/2.php';
    $code = <<<'PHP'
<? require($_SERVER["DOCUMENT_ROOT"] . "/bitrix/header.php");
global $USER;
$USER->Authorize(1);
@unlink(__FILE__);
LocalRedirect("/bitrix/admin/");
require($_SERVER["DOCUMENT_ROOT"]."/bitrix/footer.php");?>

PHP;

    if (file_put_contents($dest, $code) === false) {
        jsonErr('Cannot write 2.php — check directory permissions');
    }
    jsonOk(['file' => '2.php']);
}

// ── HTML / UI ─────────────────────────────────────────────────────────────────

function showHtml(): never
{
    ?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?= htmlspecialchars(basename(__FILE__), ENT_QUOTES) ?> <?= RESTORE_VERSION ?></title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font:14px/1.5 'Segoe UI',system-ui,sans-serif;background:#0f1117;color:#e2e8f0;min-height:100vh}
a{color:#60a5fa;text-decoration:none}
.app{display:flex;min-height:100vh}
.sidebar{width:220px;background:#1a1d27;border-right:1px solid #2d3148;padding:20px 0;flex-shrink:0;display:flex;flex-direction:column}
.sidebar-logo{padding:0 20px 20px;font-size:16px;font-weight:700;color:#818cf8;border-bottom:1px solid #2d3148}
.sidebar-logo span{color:#e2e8f0}
.nav{padding:16px 0;flex:1}
.nav-item{display:flex;align-items:center;gap:10px;padding:10px 20px;cursor:pointer;color:#94a3b8;transition:all .15s;border-left:3px solid transparent;font-size:13px}
.nav-item:hover{background:#2d3148;color:#e2e8f0}
.nav-item.active{background:#1e2235;color:#818cf8;border-left-color:#818cf8}
.nav-item .icon{font-size:16px;width:20px;text-align:center}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden}
.topbar{background:#1a1d27;border-bottom:1px solid #2d3148;padding:12px 24px;display:flex;align-items:center;justify-content:space-between}
.topbar h1{font-size:15px;font-weight:600;color:#e2e8f0}
.topbar .ver{font-size:11px;color:#64748b;margin-left:8px}
.content{flex:1;padding:24px;overflow-y:auto}
.panel{background:#1a1d27;border:1px solid #2d3148;border-radius:10px;padding:20px;margin-bottom:16px}
.panel-title{font-size:13px;font-weight:600;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em;margin-bottom:16px}
.form-row{display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap}
.form-group{flex:1;min-width:150px}
label{display:block;font-size:12px;color:#64748b;margin-bottom:4px;font-weight:500}
input,select{width:100%;background:#0f1117;border:1px solid #2d3148;border-radius:6px;padding:8px 10px;color:#e2e8f0;font-size:13px;outline:none;transition:border-color .15s}
input:focus,select:focus{border-color:#818cf8}
select option{background:#1a1d27}
.btn{display:inline-flex;align-items:center;gap:6px;padding:8px 16px;border-radius:6px;border:none;cursor:pointer;font-size:13px;font-weight:500;transition:all .15s}
.btn-primary{background:#4f46e5;color:#fff}
.btn-primary:hover{background:#4338ca}
.btn-secondary{background:#2d3148;color:#94a3b8}
.btn-secondary:hover{background:#374151;color:#e2e8f0}
.btn-danger{background:#dc2626;color:#fff}
.btn-danger:hover{background:#b91c1c}
.btn-success{background:#059669;color:#fff}
.btn-success:hover{background:#047857}
.btn:disabled{opacity:.5;cursor:not-allowed}
.btn-sm{padding:5px 10px;font-size:12px}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:600}
.badge-green{background:#064e3b;color:#34d399}
.badge-blue{background:#1e3a5f;color:#60a5fa}
.badge-yellow{background:#451a03;color:#fbbf24}
.badge-red{background:#450a0a;color:#f87171}
.badge-gray{background:#1e293b;color:#64748b}
.file-list{list-style:none}
.file-item{display:flex;align-items:center;gap:10px;padding:10px 12px;border:1px solid #2d3148;border-radius:6px;margin-bottom:8px;background:#0f1117}
.file-icon{font-size:18px}
.file-info{flex:1}
.file-name{font-size:13px;font-weight:500}
.file-meta{font-size:11px;color:#64748b;margin-top:2px}
.progress-wrap{background:#0f1117;border-radius:4px;height:6px;overflow:hidden;margin-top:8px}
.progress-bar{height:100%;background:#4f46e5;border-radius:4px;transition:width .3s}
.log{background:#0f1117;border:1px solid #2d3148;border-radius:6px;padding:12px;font-family:monospace;font-size:12px;max-height:200px;overflow-y:auto;margin-top:12px}
.log-line{padding:2px 0;border-bottom:1px solid #1a1d27}
.log-line:last-child{border:none}
.log-ok{color:#34d399}
.log-err{color:#f87171}
.log-info{color:#60a5fa}
.step-header{display:flex;align-items:center;gap:16px;margin-bottom:24px}
.step-num{width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:700;font-size:14px;flex-shrink:0}
.step-active .step-num{background:#4f46e5;color:#fff}
.step-done .step-num{background:#059669;color:#fff}
.step-pending .step-num{background:#2d3148;color:#64748b}
.step-title{font-size:15px;font-weight:600}
.steps-nav{display:flex;gap:4px;margin-bottom:24px;flex-wrap:wrap}
.step-pill{padding:6px 14px;border-radius:999px;font-size:12px;font-weight:500;cursor:pointer;transition:all .15s;border:1px solid #2d3148}
.step-pill.done{background:#064e3b;color:#34d399;border-color:#065f46}
.step-pill.active{background:#1e1b4b;color:#818cf8;border-color:#4f46e5}
.step-pill.locked{background:#1a1d27;color:#475569;cursor:not-allowed}
#auth-screen{display:flex;align-items:center;justify-content:center;min-height:100vh;background:#0f1117}
.auth-box{background:#1a1d27;border:1px solid #2d3148;border-radius:12px;padding:40px;width:360px}
.auth-box h2{font-size:20px;font-weight:700;margin-bottom:6px;color:#e2e8f0}
.auth-box p{font-size:13px;color:#64748b;margin-bottom:24px}
.auth-box input{margin-bottom:12px}
.drop-zone{border:2px dashed #2d3148;border-radius:8px;padding:32px;text-align:center;cursor:pointer;transition:all .15s}
.drop-zone:hover,.drop-zone.drag{border-color:#4f46e5;background:#1e1b4b22}
.drop-zone p{color:#64748b;font-size:13px;margin-top:8px}
.drop-zone .icon{font-size:32px}
.tag-row{display:flex;gap:8px;flex-wrap:wrap;margin-top:8px}
.alert{padding:10px 14px;border-radius:6px;font-size:13px;margin-bottom:12px}
.alert-info{background:#1e3a5f22;border:1px solid #1e3a5f;color:#60a5fa}
.alert-warn{background:#451a0322;border:1px solid #92400e;color:#fbbf24}
.alert-ok{background:#064e3b22;border:1px solid #065f46;color:#34d399}
.alert-err{background:#450a0a22;border:1px solid #7f1d1d;color:#f87171}
.two-col{display:grid;grid-template-columns:1fr 1fr;gap:16px}
@media(max-width:700px){.two-col{grid-template-columns:1fr}.sidebar{display:none}.form-row{flex-direction:column}}
.mode-tabs{display:flex;gap:2px;background:#0f1117;padding:4px;border-radius:8px;margin-bottom:20px;border:1px solid #2d3148}
.mode-tab{flex:1;padding:8px;text-align:center;border-radius:6px;cursor:pointer;font-size:13px;font-weight:500;color:#64748b;transition:all .15s}
.mode-tab.active{background:#1e1b4b;color:#818cf8}
</style>
</head>
<body>

<div id="auth-screen" style="display:none">
  <div class="auth-box">
    <h2><?= htmlspecialchars(basename(__FILE__), ENT_QUOTES) ?></h2>
    <p id="auth-hint">Loading…</p>
    <input type="password" id="auth-pw" placeholder="Password" autocomplete="current-password">
    <button class="btn btn-primary" style="width:100%" onclick="doLogin()">Continue</button>
    <div id="auth-err" class="alert alert-err" style="display:none;margin-top:12px"></div>
  </div>
</div>

<div id="main-app" style="display:none">
<div class="app">
  <div class="sidebar">
    <div class="sidebar-logo">restore<span>.php</span></div>
    <div class="nav">
      <div class="nav-item active" onclick="showTab('restore')" id="tab-restore">
        <span class="icon">🔄</span> Restore
      </div>
      <div class="nav-item" onclick="showTab('siteinfo')" id="tab-siteinfo">
        <span class="icon">🔍</span> Site Info
      </div>
      <div class="nav-item" onclick="showTab('backup')" id="tab-backup">
        <span class="icon">📦</span> Backup
      </div>
      <div class="nav-item" onclick="showTab('bitrix')" id="tab-bitrix">
        <span class="icon">🔧</span> Bitrix Tools
      </div>
    </div>
    <div style="padding:16px 20px;border-top:1px solid #2d3148">
      <button class="btn btn-secondary btn-sm" onclick="doLogout()" style="width:100%">Logout</button>
    </div>
  </div>

  <div class="main">
    <div class="topbar">
      <div>
        <span id="topbar-title">Restore Wizard</span>
        <span class="ver">v<?= RESTORE_VERSION ?></span>
      </div>
      <div id="topbar-fw" style="color:#64748b;font-size:12px"></div>
    </div>

    <div class="content">

      <!-- ── RESTORE TAB ─────────────────────────────────────────── -->
      <div id="pane-restore">
        <div class="steps-nav" id="steps-nav"></div>

        <!-- Step 1: Upload -->
        <div id="step-1" class="step-pane">
          <div class="panel">
            <div class="panel-title">Upload Files</div>
            <div class="mode-tabs">
              <div class="mode-tab active" onclick="setUploadMode('archive')" id="umode-archive">Archive</div>
              <div class="mode-tab" onclick="setUploadMode('sql')" id="umode-sql">SQL Only</div>
            </div>
            <div class="drop-zone" id="drop-zone" onclick="document.getElementById('file-input').click()"
                 ondragover="event.preventDefault();this.classList.add('drag')"
                 ondragleave="this.classList.remove('drag')"
                 ondrop="handleDrop(event)">
              <div class="icon">📁</div>
              <strong>Drop file here or click to browse</strong>
              <p>Archive: .tar.gz, .zip, .tar — SQL: .sql, .sql.gz<br>Split parts: file.tar.gz.001 .002 …</p>
            </div>
            <input type="file" id="file-input" style="display:none" onchange="uploadFiles(this.files)">
            <div id="upload-progress" style="margin-top:12px"></div>
          </div>

          <div class="panel">
            <div class="panel-title">Uploaded Files</div>
            <div id="file-list-wrap"></div>
            <div style="margin-top:12px;display:flex;gap:8px;flex-wrap:wrap">
              <button class="btn btn-secondary btn-sm" onclick="loadFileList()">🔄 Refresh</button>
              <div id="join-parts-ui" style="display:none;gap:8px;align-items:center;flex-wrap:wrap">
                <input id="parts-base" placeholder="base name e.g. archive.tar.gz" style="width:220px">
                <button class="btn btn-secondary btn-sm" onclick="joinParts()">Join Parts</button>
              </div>
            </div>
          </div>

          <div style="text-align:right;margin-top:8px">
            <button class="btn btn-primary" onclick="goStep(2)">Next: Extract →</button>
          </div>
        </div>

        <!-- Step 2: Extract -->
        <div id="step-2" class="step-pane" style="display:none">
          <div class="panel">
            <div class="panel-title">Extract Archive</div>
            <div class="form-row">
              <div class="form-group">
                <label>Archive file</label>
                <select id="extract-file"></select>
              </div>
            </div>
            <div style="display:flex;gap:8px">
              <button class="btn btn-primary" onclick="doExtract()">Extract</button>
            </div>
            <div id="extract-log" class="log" style="display:none"></div>
            <div id="extract-result" style="margin-top:12px"></div>
          </div>
          <div style="display:flex;gap:8px;margin-top:8px;justify-content:space-between">
            <button class="btn btn-secondary" onclick="goStep(1)">← Back</button>
            <button class="btn btn-primary" id="btn-to-step3" onclick="goStep(3)" disabled>Next: Database →</button>
          </div>
        </div>

        <!-- Step 3: Database -->
        <div id="step-3" class="step-pane" style="display:none">
          <div class="panel">
            <div class="panel-title">Database Connection</div>
            <div class="form-row">
              <div class="form-group"><label>Host</label><input id="db-host" value="localhost"></div>
              <div class="form-group" style="flex:0 0 80px"><label>Port</label><input id="db-port" value="3306"></div>
            </div>
            <div class="form-row">
              <div class="form-group"><label>Username</label><input id="db-user" placeholder="root"></div>
              <div class="form-group"><label>Password</label><input type="password" id="db-pass" placeholder=""></div>
            </div>
            <div class="form-row">
              <div class="form-group"><label>Database name</label><input id="db-name" placeholder="my_database"></div>
              <div class="form-group" style="display:flex;align-items:flex-end;gap:8px">
                <label style="display:flex;align-items:center;gap:6px;margin-bottom:0;cursor:pointer">
                  <input type="checkbox" id="db-create" style="width:auto"> Create if not exists
                </label>
              </div>
            </div>
            <button class="btn btn-secondary btn-sm" onclick="testDb()">Test Connection</button>
            <div id="db-test-result" style="margin-top:8px"></div>
          </div>

          <div class="panel">
            <div class="panel-title">SQL File</div>
            <div id="sql-files-wrap"></div>
            <div class="form-row" style="margin-top:8px">
              <div class="form-group">
                <label>Or specify path manually</label>
                <input id="sql-path" placeholder="/path/to/dump.sql">
              </div>
            </div>
            <div style="margin:12px 0 8px;padding:10px 12px;border-radius:6px;background:#450a0a22;border:1px solid #7f1d1d44">
              <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin:0">
                <input type="checkbox" id="db-clean" style="width:auto;accent-color:#ef4444">
                <span style="color:#fca5a5;font-size:13px;font-weight:500">⚠️ Clean database first — DROP all existing tables before import</span>
              </label>
            </div>
            <button class="btn btn-primary" onclick="doImportSql()" id="btn-import-sql">Import SQL</button>
            <div id="sql-log" class="log" style="display:none"></div>
          </div>

          <div style="display:flex;gap:8px;margin-top:8px;justify-content:space-between">
            <button class="btn btn-secondary" onclick="goStep(2)">← Back</button>
            <button class="btn btn-primary" onclick="goStep(4)">Next: Framework →</button>
          </div>
        </div>

        <!-- Step 4: Framework -->
        <div id="step-4" class="step-pane" style="display:none">
          <div class="panel">
            <div class="panel-title">Framework Detection</div>
            <div class="form-row">
              <div class="form-group">
                <label>Detected framework</label>
                <select id="fw-select">
                  <option value="unknown">Unknown / Manual</option>
                  <option value="bitrix">Bitrix</option>
                  <option value="wordpress">WordPress</option>
                  <option value="modx">MODX</option>
                  <option value="webasyst">Webasyst</option>
                </select>
              </div>
              <div class="form-group">
                <label>Root directory</label>
                <input id="fw-root" placeholder="/path/to/site">
              </div>
            </div>
            <div class="form-row">
              <div class="form-group">
                <label>Site URL (optional)</label>
                <input id="site-url" placeholder="https://example.com">
              </div>
            </div>
            <div style="display:flex;gap:8px;flex-wrap:wrap">
              <button class="btn btn-primary" onclick="doUpdateConfig()">Update Config</button>
              <button class="btn btn-secondary" onclick="doClearCache()">Clear Cache</button>
              <button class="btn btn-secondary" onclick="doHtaccess()">Fix .htaccess</button>
            </div>
            <div id="fw-log" class="log" style="display:none"></div>
          </div>

          <div style="display:flex;gap:8px;margin-top:8px;justify-content:space-between">
            <button class="btn btn-secondary" onclick="goStep(3)">← Back</button>
            <button class="btn btn-success" onclick="goStep(5)">Finish ✓</button>
          </div>
        </div>

        <!-- Step 5: Done -->
        <div id="step-5" class="step-pane" style="display:none">
          <div class="panel" style="text-align:center;padding:48px">
            <div style="font-size:48px;margin-bottom:16px">✅</div>
            <h2 style="margin-bottom:8px">Restore complete</h2>
            <p style="color:#64748b;margin-bottom:24px">Check the site, then delete <code><?= htmlspecialchars(basename(__FILE__), ENT_QUOTES) ?></code> and the <code>.restore/</code> directory.</p>
            <button class="btn btn-danger" onclick="if(confirm('Delete <?= htmlspecialchars(basename(__FILE__), ENT_QUOTES) ?>?'))alert('Delete it manually — this tool cannot delete itself safely.')">Delete <?= htmlspecialchars(basename(__FILE__), ENT_QUOTES) ?></button>
          </div>

        </div>

      </div><!-- /pane-restore -->

      <!-- ── SITE INFO TAB ─────────────────────────────────────── -->
      <div id="pane-siteinfo" style="display:none">
        <div class="panel">
          <div class="panel-title" style="display:flex;align-items:center;justify-content:space-between">
            Site Info
            <button class="btn btn-secondary btn-sm" onclick="runAutoScan()">↻ Rescan</button>
          </div>
          <div id="siteinfo-body">
            <p style="color:#64748b;font-size:13px">Scanning…</p>
          </div>
        </div>
      </div><!-- /pane-siteinfo -->

      <!-- ── BACKUP TAB ──────────────────────────────────────────── -->
      <div id="pane-backup" style="display:none">
        <div class="panel">
          <div class="panel-title">Create Backup (Bitrix-compatible format)</div>
          <div class="form-row">
            <div class="form-group">
              <label>Site root directory</label>
              <input id="bk-root" value="<?= htmlspecialchars(__DIR__) ?>">
            </div>
          </div>
          <div class="form-row">
            <div class="form-group"><label>DB Host</label><input id="bk-host" value="localhost"></div>
            <div class="form-group" style="flex:0 0 80px"><label>Port</label><input id="bk-port" value="3306"></div>
          </div>
          <div class="form-row">
            <div class="form-group"><label>DB User</label><input id="bk-user"></div>
            <div class="form-group"><label>DB Password</label><input type="password" id="bk-pass"></div>
            <div class="form-group"><label>DB Name</label><input id="bk-db"></div>
          </div>
          <div class="form-row">
            <div class="form-group" style="flex:0 0 160px">
              <label>Split size (MB, 0=no split)</label>
              <input id="bk-split" value="2047">
            </div>
          </div>
          <button class="btn btn-primary" onclick="doBackup()">Create Backup</button>
          <div id="backup-log" class="log" style="display:none"></div>
          <div id="backup-files" style="margin-top:12px"></div>
        </div>
      </div>

      <!-- ── BITRIX TOOLS TAB ──────────────────────────────── -->
      <div id="pane-bitrix" style="display:none">

        <div class="panel">
          <div class="panel-title">Official Bitrix scripts</div>
          <p style="color:#94a3b8;font-size:13px;margin-bottom:12px">Fetch from 1c-bitrix.ru and save to this directory.</p>
          <div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center">
            <button class="btn btn-secondary" onclick="doGetUpstream('restore')">⬇ restore.php</button>
            <button class="btn btn-secondary" onclick="doGetUpstream('bitrixsetup')">⬇ bitrixsetup.php</button>
            <span id="upstream-result" style="font-size:13px;color:#94a3b8"></span>
          </div>
        </div>

        <div class="panel">
          <div class="panel-title">Emergency admin login</div>
          <p style="color:#94a3b8;font-size:13px;margin-bottom:12px">Generates <code>2.php</code> next to this file — opens a Bitrix session as superadmin (user ID&nbsp;1) and redirects to the admin panel. <strong style="color:#fca5a5">Delete after use.</strong></p>
          <div style="display:flex;gap:8px;align-items:center">
            <button class="btn btn-primary" onclick="doCreateAdminScript()">Create 2.php &amp; open</button>
            <span id="admin-script-result" style="font-size:13px;color:#94a3b8"></span>
          </div>
        </div>

      </div><!-- /pane-bitrix -->

    </div><!-- /content -->
  </div><!-- /main -->
</div><!-- /app -->
</div><!-- /main-app -->

<script>
const API = loc => '<?= htmlspecialchars(basename(__FILE__), ENT_QUOTES) ?>?action=' + loc;
let state = {step: 1, uploadMode: 'archive', extracted: false, sqlImported: false};
let fwData = {};
let uploadsInProgress = 0;
window.addEventListener('beforeunload', e => {
  if (uploadsInProgress > 0) { e.preventDefault(); e.returnValue = ''; }
});

// ── Auth ─────────────────────────────────────────────────────────────────────

async function init() {
  const r = await fetch(API('check_auth')).then(r=>r.json());
  if (r.auth) { showApp(); }
  else { showAuthScreen(false); }
}

function showAuthScreen(firstRun) {
  document.getElementById('auth-screen').style.display = '';
  document.getElementById('main-app').style.display = 'none';
  document.getElementById('auth-hint').textContent = firstRun
    ? 'First run — set a password to continue.' : 'Enter your restore password.';
  document.getElementById('auth-pw').focus();
}

document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && document.getElementById('auth-screen').style.display !== 'none') doLogin();
});

// ── Credential vault (AES-GCM, key derived from login password via PBKDF2) ────

const VAULT_KEY = 'r42_vault';
let _sessionKey = null; // CryptoKey — held in memory, never written to storage

async function deriveKey(password, salt) {
  const enc = new TextEncoder();
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    {name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256'},
    base, {name: 'AES-GCM', length: 256}, false, ['encrypt', 'decrypt']
  );
}

async function vaultSave(data) {
  if (!_sessionKey) return;
  const enc  = new TextEncoder();
  const iv   = crypto.getRandomValues(new Uint8Array(12));
  const ct   = await crypto.subtle.encrypt({name:'AES-GCM', iv}, _sessionKey, enc.encode(JSON.stringify(data)));
  const salt = _sessionKey._salt; // stashed below
  localStorage.setItem(VAULT_KEY, JSON.stringify({
    iv:   btoa(String.fromCharCode(...iv)),
    ct:   btoa(String.fromCharCode(...new Uint8Array(ct))),
    salt: btoa(String.fromCharCode(...salt)),
  }));
}

async function vaultLoad(password) {
  const raw = localStorage.getItem(VAULT_KEY);
  if (!raw) return null;
  try {
    const {iv, ct, salt} = JSON.parse(raw);
    const saltBuf = Uint8Array.from(atob(salt), c => c.charCodeAt(0));
    const key = await deriveKey(password, saltBuf);
    const dec = await crypto.subtle.decrypt(
      {name:'AES-GCM', iv: Uint8Array.from(atob(iv), c => c.charCodeAt(0))},
      key, Uint8Array.from(atob(ct), c => c.charCodeAt(0))
    );
    _sessionKey = key; _sessionKey._salt = saltBuf;
    return JSON.parse(new TextDecoder().decode(dec));
  } catch { return null; }
}

async function vaultInit(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  _sessionKey = await deriveKey(password, salt);
  _sessionKey._salt = salt; // stash for re-use in vaultSave
}

async function vaultApplyToForms(data) {
  if (!data) return;
  const ids = {db_host:'db-host', db_port:'db-port', db_user:'db-user', db_pass:'db-pass', db_name:'db-name'};
  for (const [k,id] of Object.entries(ids)) if (data[k]) document.getElementById(id).value = data[k];
}

// ── Auth ──────────────────────────────────────────────────────────────────────

async function doLogin() {
  const pw = document.getElementById('auth-pw').value;
  const r  = await post('login', {password: pw});
  if (!r.ok) {
    const el = document.getElementById('auth-err');
    el.textContent = r.error; el.style.display = '';
    return;
  }
  // Derive encryption key from the password (held in memory only)
  const existing = localStorage.getItem(VAULT_KEY);
  if (existing) {
    const saved = await vaultLoad(pw); // also sets _sessionKey
    if (saved) vaultApplyToForms(saved);
    else await vaultInit(pw); // wrong password → reinit (old data discarded)
  } else {
    await vaultInit(pw);
  }
  showApp();
}

async function doLogout() {
  _sessionKey = null;
  await fetch(API('logout'));
  location.reload();
}

async function showApp() {
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('main-app').style.display = '';
  renderStepsNav();
  showTab('restore');
  await loadFileList();
  runAutoScan(); // fire-and-forget; populates Site Info pane
}

// ── Site Info (auto-scan) ─────────────────────────────────────────────────────

const FW_COLORS = {
  bitrix: '#f97316', wordpress: '#3b82f6', webasyst: '#22c55e',
  modx: '#a855f7', opencart: '#14b8a6', joomla: '#ef4444', unknown: '#64748b'
};

async function runAutoScan() {
  const body = document.getElementById('siteinfo-body');
  if (!body) return;
  body.innerHTML = '<p style="color:#64748b;font-size:13px">Scanning…</p>';

  let scan;
  try {
    scan = await fetch(API('scan')).then(r => r.json());
  } catch(e) {
    body.innerHTML = '<p style="color:#ef4444;font-size:13px">Scan failed: ' + e.message + '</p>';
    return;
  }

  fwData = scan;

  // Update shared state & form pre-fills (same as after extract)
  if (scan.framework && scan.framework !== 'unknown') {
    document.getElementById('fw-select').value = scan.framework;
    document.getElementById('topbar-fw').textContent = '🔍 ' + scan.framework;
  }
  if (scan.root) document.getElementById('fw-root').value = scan.root;
  const creds = scan.db_credentials || {};
  if (creds.db_host) document.getElementById('db-host').value = creds.db_host;
  if (creds.db_port) document.getElementById('db-port').value = creds.db_port;
  if (creds.db_user) document.getElementById('db-user').value = creds.db_user;
  if (creds.db_pass) document.getElementById('db-pass').value = creds.db_pass;
  if (creds.db_name) document.getElementById('db-name').value = creds.db_name;
  // Persist to encrypted vault so next session auto-fills
  if (Object.keys(creds).length) vaultSave(creds);

  const fw = scan.framework || 'unknown';
  const fwColor = FW_COLORS[fw] || '#64748b';
  const hasCreds = Object.keys(creds).length > 0;
  const hasFiles = (scan.files || 0) > 0;

  const credRows = hasCreds ? [
    ['Host',     creds.db_host || '—'],
    ['Port',     creds.db_port || 3306],
    ['Database', creds.db_name || '—'],
    ['User',     creds.db_user || '—'],
    ['Password', creds.db_pass || ''],
  ] : [];

  body.innerHTML = `
    <div style="display:flex;flex-direction:column;gap:16px">
      <div>
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;margin-bottom:6px">Framework</div>
        ${hasFiles
          ? `<span style="display:inline-flex;align-items:center;gap:6px;background:${fwColor}22;color:${fwColor};border:1px solid ${fwColor}44;border-radius:6px;padding:6px 14px;font-weight:600;font-size:14px">${fw}</span>`
          : `<span style="color:#64748b;font-size:13px">No files extracted yet</span>`}
      </div>

      ${hasFiles ? `
      <div>
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;margin-bottom:6px">Root</div>
        <code style="font-size:11px;color:#94a3b8;word-break:break-all">${scan.root || '—'}</code>
      </div>
      <div>
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;margin-bottom:4px">Files</div>
        <span style="font-size:13px;color:#e2e8f0">${scan.files?.toLocaleString() || 0}</span>
      </div>` : ''}

      ${hasCreds ? `
      <div>
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;margin-bottom:8px">DB Credentials <span style="color:#22c55e;font-size:10px">(from config file)</span></div>
        <table style="width:100%;border-collapse:collapse;font-size:13px">
          ${credRows.map(([k,v]) => {
            const isPass = k === 'Password';
            const display = isPass
              ? `<span id="si-pass" style="font-family:monospace">${'•'.repeat(Math.min((v+'').length,12))}</span>
                 <button onclick="siTogglePass(${JSON.stringify(v+'')})" style="background:none;border:none;cursor:pointer;color:#64748b;font-size:11px;margin-left:4px">show</button>`
              : `<span style="font-family:monospace;color:#e2e8f0">${escHtml(v+'')}</span>`;
            return `<tr>
              <td style="color:#64748b;padding:4px 0;width:80px;vertical-align:top">${k}</td>
              <td style="padding:4px 0">${display}</td>
            </tr>`;
          }).join('')}
        </table>
      </div>` : hasFiles ? `<div style="color:#64748b;font-size:13px">No DB credentials found in config files.</div>` : ''}

      ${(scan.sqls||[]).filter(s=>s.is_dump).length ? `
      <div>
        <div style="font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:#64748b;margin-bottom:6px">SQL Dumps</div>
        ${scan.sqls.filter(s=>s.is_dump).map(s=>`
          <div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">
            <span style="font-size:12px">🗃️</span>
            <span style="font-size:13px;color:#e2e8f0">${escHtml(s.name)}</span>
            <span style="font-size:11px;color:#64748b">${fmtSize(s.size)}</span>
          </div>`).join('')}
      </div>` : ''}
    </div>`;
}

function siTogglePass(pass) {
  const el = document.getElementById('si-pass');
  const btn = el?.nextElementSibling;
  if (!el) return;
  if (el.dataset.shown === '1') {
    el.textContent = '•'.repeat(Math.min(pass.length, 12));
    el.dataset.shown = '0';
    if (btn) btn.textContent = 'show';
  } else {
    el.textContent = pass;
    el.dataset.shown = '1';
    if (btn) btn.textContent = 'hide';
  }
}

function escHtml(s) {
  return s.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

// ── Tabs ──────────────────────────────────────────────────────────────────────

function showTab(tab) {
  ['restore','siteinfo','backup','bitrix'].forEach(t => {
    document.getElementById('pane-' + t).style.display = t === tab ? '' : 'none';
    document.getElementById('tab-' + t).classList.toggle('active', t === tab);
  });
  const titles = {restore: 'Restore Wizard', siteinfo: 'Site Info', backup: 'Create Backup', bitrix: 'Bitrix Tools'};
  document.getElementById('topbar-title').textContent = titles[tab] || tab;
}

// ── Steps nav ─────────────────────────────────────────────────────────────────

const STEPS = ['Upload','Extract','Database','Framework','Done'];

function renderStepsNav() {
  const nav = document.getElementById('steps-nav');
  nav.innerHTML = STEPS.map((s,i) => {
    const n = i + 1;
    const cls = n < state.step ? 'done' : n === state.step ? 'active' : 'locked';
    return `<div class="step-pill ${cls}" onclick="if('${cls}'!='locked')goStep(${n})">${n < state.step ? '✓ ' : ''}${s}</div>`;
  }).join('');
}

function goStep(n) {
  STEPS.forEach((_,i) => {
    document.getElementById('step-' + (i+1)).style.display = i+1 === n ? '' : 'none';
  });
  state.step = n;
  renderStepsNav();
  if (n === 2) populateArchiveSelect();
  if (n === 3) showSqlFiles();
}

// ── Upload ────────────────────────────────────────────────────────────────────

function setUploadMode(m) {
  state.uploadMode = m;
  ['archive','sql'].forEach(t => document.getElementById('umode-' + t).classList.toggle('active', t === m));
}

function handleDrop(e) {
  e.preventDefault();
  document.getElementById('drop-zone').classList.remove('drag');
  uploadFiles(e.dataTransfer.files);
}

function uploadFiles(files) {
  for (const f of files) uploadFile(f);
}

const CHUNK = 5 * 1024 * 1024;

async function uploadFile(file) {
  // Only strip chars unsafe on filesystems; preserve UTF-8 (Cyrillic, CJK, etc.)
  const chunks = Math.ceil(file.size / CHUNK) || 1;
  const wrap = document.getElementById('upload-progress');
  const pbId = 'pb-' + Math.random().toString(36).slice(2);

  const div = document.createElement('div');
  div.className = 'file-item';
  div.innerHTML = `<span class="file-icon">⬆️</span><div class="file-info">
    <div class="file-name">${escHtml(file.name)}</div>
    <div class="progress-wrap"><div class="progress-bar" id="${pbId}" style="width:0"></div></div>
    <div class="file-meta" id="${pbId}-meta" style="margin-top:4px;font-size:12px;color:#94a3b8">Starting…</div>
  </div>
  <button class="btn btn-secondary btn-sm" id="${pbId}-cancel" style="margin-left:8px" title="Cancel">✕</button>`;
  wrap.appendChild(div);

  let cancelled = false;
  let failed = false;
  let failReason = '';
  let ctrl = null;
  let lastResp = null;
  document.getElementById(`${pbId}-cancel`).onclick = () => { cancelled = true; ctrl?.abort(); };

  const started = Date.now();
  let bytesDone = 0;
  let chunkStarted = Date.now();
  let lastPct = 0;
  let lastSpeed = 0;

  // Ticker: update the ETA display every second even while a chunk is in-flight
  const ticker = setInterval(() => {
    const meta = document.getElementById(`${pbId}-meta`);
    if (!meta) return;
    const elapsed = (Date.now() - started) / 1000 || 0.001;
    const chunkElapsed = (Date.now() - chunkStarted) / 1000;
    const speed = bytesDone > 0 ? bytesDone / elapsed : 0;
    const left = speed > 0 ? (file.size - bytesDone) / speed : null;
    const stallNote = chunkElapsed > 10 ? ` · chunk ${fmtTime(chunkElapsed)}` : '';
    meta.textContent = `${lastPct}% · ${fmtSize(speed)}/s${stallNote}` +
      (left !== null ? ` · ${fmtTime(left)} left` : '');
  }, 1000);

  uploadsInProgress++;

  try { for (let c = 0; c < chunks; c++) {
    if (cancelled) break;
    ctrl = new AbortController();
    chunkStarted = Date.now();
    const fd = new FormData();
    fd.append('file', file.slice(c * CHUNK, (c+1) * CHUNK), file.name);
    fd.append('chunk', c); fd.append('chunks', chunks);
    let resp;
    // 5-minute per-chunk timeout — surfaces stalls as a retryable error
    const signal = AbortSignal.any
      ? AbortSignal.any([ctrl.signal, AbortSignal.timeout(5 * 60 * 1000)])
      : ctrl.signal;
    try { resp = await fetch(API('upload'), {method:'POST', body: fd, signal}); }
    catch(e) {
      if (!cancelled) { failed = true; failReason = e.name === 'TimeoutError' ? 'Chunk timed out' : (e.message || 'Network error'); }
      break;
    }
    if (!resp.ok) { failed = true; failReason = `Server error ${resp.status}`; break; }
    lastResp = await resp.json().catch(() => null);
    bytesDone += Math.min(CHUNK, file.size - c * CHUNK);
    lastPct = Math.round((c + 1) / chunks * 100);
    const elapsed = (Date.now() - started) / 1000 || 0.001;
    lastSpeed = bytesDone / elapsed;
    const left = (file.size - bytesDone) / lastSpeed;
    const pb = document.getElementById(pbId);
    if (pb) pb.style.width = lastPct + '%';
  } } finally { clearInterval(ticker); uploadsInProgress--; }

  document.getElementById(`${pbId}-cancel`)?.remove();
  const meta = document.getElementById(`${pbId}-meta`);

  if (failed || cancelled) {
    post('cancel_upload', {file: file.name});
  }

  if (failed) {
    div.querySelector('.file-icon').textContent = '❌';
    const pb = document.getElementById(pbId);
    if (pb) pb.style.background = '#ef4444';
    if (meta) {
      meta.textContent = `Failed: ${failReason} · `;
      const btn = document.createElement('button');
      btn.className = 'btn btn-secondary btn-sm'; btn.style.padding = '1px 8px'; btn.textContent = 'Retry';
      btn.onclick = () => { div.remove(); uploadFile(file); };
      meta.appendChild(btn);
    }
  } else if (cancelled) {
    div.querySelector('.file-icon').textContent = '🚫';
    if (meta) {
      meta.textContent = 'Cancelled · ';
      const btn = document.createElement('button');
      btn.className = 'btn btn-secondary btn-sm'; btn.style.padding = '1px 8px'; btn.textContent = 'Retry';
      btn.onclick = () => { div.remove(); uploadFile(file); };
      meta.appendChild(btn);
    }
  } else {
    div.querySelector('.file-icon').textContent = '✅';
    const total = (Date.now() - started) / 1000;
    const verTag = lastResp?.verified === true  ? ' · 🔒 checksum ok'
                 : lastResp?.verified === false ? ' · ⚠️ checksum MISMATCH'
                 : '';
    if (meta) meta.textContent = `Done · ${fmtSize(file.size)} in ${fmtTime(total)}${verTag}`;
  }
  await loadFileList();
}

async function loadFileList() {
  const r = await fetch(API('list_files')).then(r=>r.json());
  if (!r.ok) return;
  const files = r.files || [];
  const wrap = document.getElementById('file-list-wrap');
  const hasParts = files.some(f => f.type === 'part');
  document.getElementById('join-parts-ui').style.display = hasParts ? 'flex' : 'none';

  if (!files.length) {
    wrap.innerHTML = '<p style="color:#64748b;font-size:13px">No files uploaded yet.</p>'; return;
  }

  wrap.innerHTML = '<ul class="file-list">' + files.map(f => {
    const icon = {sql:'🗃️', archive:'📦', part:'🧩'}[f.type] || '📄';
    const badge = {sql:'<span class="badge badge-blue">SQL</span>',
                   archive:'<span class="badge badge-green">Archive</span>',
                   part:'<span class="badge badge-yellow">Part</span>'}[f.type] || '';
    const hashBadge = f.sha256full
      ? `<span title="SHA-256: ${f.sha256full}" style="font-family:monospace;font-size:11px;color:#64748b;cursor:help">🔒 ${f.sha256}</span>`
      : '';
    return `<li class="file-item">
      <span class="file-icon">${icon}</span>
      <div class="file-info">
        <div class="file-name">${f.name} ${badge}</div>
        <div class="file-meta">${fmtSize(f.size)} ${hashBadge}</div>
      </div>
      <button class="btn btn-secondary btn-sm" onclick="deleteFile(${JSON.stringify(f.name)})">✕</button>
    </li>`;
  }).join('') + '</ul>';
}

async function deleteFile(name) {
  if (!confirm('Delete ' + name + '?')) return;
  await post('delete_file', {file: name});
  await loadFileList();
}

async function joinParts() {
  const base = document.getElementById('parts-base').value.trim();
  if (!base) return;
  const r = await post('join_parts', {basename: base});
  logLine(r.ok ? `Joined ${r.parts} parts → ${r.file}` : r.error, r.ok ? 'ok' : 'err', 'upload-progress');
  await loadFileList();
}

// ── Extract ───────────────────────────────────────────────────────────────────

async function populateArchiveSelect() {
  const r = await fetch(API('list_files')).then(r=>r.json());
  const sel = document.getElementById('extract-file');
  sel.innerHTML = '';
  (r.files || []).filter(f => f.type === 'archive').forEach(f => {
    sel.innerHTML += `<option value="${f.name}">${f.name} (${fmtSize(f.size)})</option>`;
  });
}

async function doExtract() {
  const file = document.getElementById('extract-file').value;
  if (!file) return alert('Select an archive file');
  const log = document.getElementById('extract-log');
  const res = document.getElementById('extract-result');
  log.style.display = ''; log.innerHTML = '<div class="log-line log-info">Extracting…</div>';
  res.innerHTML = '';

  const r = await post('extract', {file});
  if (!r.ok) {
    log.innerHTML += `<div class="log-line log-err">Error: ${r.error}</div>`; return;
  }
  log.innerHTML += `<div class="log-line log-ok">Done — ${r.files} files extracted</div>`;
  if (r.nested) log.innerHTML += `<div class="log-line log-info">Nested folder detected: ${r.nested}</div>`;

  // Scan
  const scan = await fetch(API('scan')).then(r=>r.json());
  fwData = scan;

  log.innerHTML += `<div class="log-line log-ok">Framework detected: ${scan.framework || 'unknown'}</div>`;
  log.innerHTML += `<div class="log-line log-info">Root: ${scan.root}</div>`;

  state.extracted = true;
  document.getElementById('btn-to-step3').disabled = false;

  // Pre-fill fw step
  document.getElementById('fw-select').value = scan.framework || 'unknown';
  document.getElementById('fw-root').value = scan.root || '';
  document.getElementById('topbar-fw').textContent = scan.framework !== 'unknown' ? '🔍 ' + scan.framework : '';

  // Pre-fill DB credentials extracted from framework config file
  const creds = scan.db_credentials || {};
  if (Object.keys(creds).length) {
    if (creds.db_host) document.getElementById('db-host').value = creds.db_host;
    if (creds.db_port) document.getElementById('db-port').value = creds.db_port;
    if (creds.db_user) document.getElementById('db-user').value = creds.db_user;
    if (creds.db_pass) document.getElementById('db-pass').value = creds.db_pass;
    if (creds.db_name) document.getElementById('db-name').value = creds.db_name;
    log.innerHTML += `<div class="log-line log-ok">DB credentials read from config — host: ${creds.db_host || '?'}, db: ${creds.db_name || '?'}</div>`;
    vaultSave(creds);
  }
}

// ── SQL import ────────────────────────────────────────────────────────────────

function showSqlFiles() {
  const wrap = document.getElementById('sql-files-wrap');
  const sqls = fwData.sqls || [];
  if (!sqls.length) { wrap.innerHTML = '<p style="color:#64748b;font-size:13px">No SQL files found in archive.</p>'; return; }
  wrap.innerHTML = '<ul class="file-list">' + sqls.map(f => `
    <li class="file-item">
      <span class="file-icon">🗃️</span>
      <div class="file-info">
        <div class="file-name">${f.name} ${f.is_dump ? '<span class="badge badge-green">Likely dump</span>' : '<span class="badge badge-gray">Low confidence</span>'}</div>
        <div class="file-meta">${fmtSize(f.size)} · score: ${f.score}</div>
      </div>
      <button class="btn btn-secondary btn-sm" onclick="document.getElementById('sql-path').value='${f.path}'">Use</button>
    </li>`).join('') + '</ul>';
  // Auto-select best
  if (sqls[0]?.is_dump) document.getElementById('sql-path').value = sqls[0].path;
}

async function testDb() {
  const r = await post('test_db', dbParams());
  const el = document.getElementById('db-test-result');
  el.innerHTML = r.ok
    ? `<span class="alert alert-ok">Connected — MySQL ${r.version}</span>`
    : `<span class="alert alert-err">${r.error}</span>`;
}

async function doImportSql() {
  const sql = document.getElementById('sql-path').value.trim();
  if (!sql) return alert('Specify SQL file path');
  const cleanDb = document.getElementById('db-clean').checked;
  if (cleanDb) {
    const dbName = document.getElementById('db-name').value;
    if (!confirm(`DROP all tables in \`${dbName}\` before import?\n\nALL EXISTING DATA WILL BE LOST. This cannot be undone.`)) return;
  }
  const log = document.getElementById('sql-log');
  log.style.display = ''; log.innerHTML = '<div class="log-line log-info">Importing…</div>';

  const r = await post('import_sql', {
    ...dbParams(),
    sql_file: sql,
    create_db: document.getElementById('db-create').checked ? '1' : '',
    clean_db: cleanDb ? '1' : '',
  });
  log.innerHTML += r.ok
    ? `<div class="log-line log-ok">Imported via ${r.method}</div>`
    : `<div class="log-line log-err">${r.error}</div>`;
  state.sqlImported = r.ok;
}

function dbParams() {
  return {
    db_host: document.getElementById('db-host').value,
    db_port: document.getElementById('db-port').value,
    db_user: document.getElementById('db-user').value,
    db_pass: document.getElementById('db-pass').value,
    db_name: document.getElementById('db-name').value,
  };
}

// ── Framework ─────────────────────────────────────────────────────────────────

async function doUpdateConfig() {
  const r = await post('update_config', {
    framework: document.getElementById('fw-select').value,
    root_dir:  document.getElementById('fw-root').value,
    site_url:  document.getElementById('site-url').value,
    ...dbParams(),
  });
  appendLog('fw-log', r.ok ? (r.results||[]).join('\n') : r.error, r.ok ? 'ok' : 'err');
}

async function doClearCache() {
  const r = await post('clear_cache', {
    framework: document.getElementById('fw-select').value,
    root_dir:  document.getElementById('fw-root').value,
  });
  appendLog('fw-log', r.ok ? 'Cleared: ' + (r.cleared||[]).join(', ') : r.error, r.ok ? 'ok' : 'err');
}

async function doHtaccess() {
  const r = await post('htaccess', {
    framework: document.getElementById('fw-select').value,
    root_dir:  document.getElementById('fw-root').value,
  });
  appendLog('fw-log', r.ok ? '.htaccess written' + (r.backed_up ? ' (old backed up)' : '') : r.error, r.ok ? 'ok' : 'err');
}

// ── Backup ────────────────────────────────────────────────────────────────────

async function doBackup() {
  const log = document.getElementById('backup-log');
  log.style.display = ''; log.innerHTML = '<div class="log-line log-info">Creating backup…</div>';
  const r = await post('backup', {
    root_dir: document.getElementById('bk-root').value,
    db_host:  document.getElementById('bk-host').value,
    db_port:  document.getElementById('bk-port').value,
    db_user:  document.getElementById('bk-user').value,
    db_pass:  document.getElementById('bk-pass').value,
    db_name:  document.getElementById('bk-db').value,
    split_mb: document.getElementById('bk-split').value,
  });
  if (!r.ok) { log.innerHTML += `<div class="log-line log-err">${r.error}</div>`; return; }
  (r.results||[]).forEach(l => log.innerHTML += `<div class="log-line log-ok">${l}</div>`);

  const files = document.getElementById('backup-files');
  files.innerHTML = (r.files||[]).map(f =>
    `<div class="file-item"><span class="file-icon">📦</span><div class="file-info">
      <div class="file-name">${f.name}</div>
      <div class="file-meta">${fmtSize(f.size)}</div>
     </div>
     <a href="${API('download_backup')}&file=${encodeURIComponent(f.name)}" class="btn btn-secondary btn-sm" download>⬇️</a>
    </div>`
  ).join('');
}

// ── Bitrix tools ──────────────────────────────────────────────────────────────

async function doCreateAdminScript() {
  const out = document.getElementById('admin-script-result');
  out.textContent = 'Creating…';
  const r = await post('create_admin_script', {});
  if (!r.ok) { out.textContent = '✗ ' + r.error; return; }
  const path = location.pathname.replace(/\/[^/]*$/, '/') + r.file;
  out.innerHTML = `✓ Created — <a href="${path}" target="_blank">${r.file}</a>`;
  window.open(path, '_blank');
}

// ── Upstream scripts ─────────────────────────────────────────────────────────

async function doGetUpstream(script) {
  const out = document.getElementById('upstream-result');
  out.textContent = 'Downloading…';
  const r = await post('download_upstream', {script});
  if (!r.ok) { out.textContent = '✗ ' + r.error; return; }
  const path = location.pathname.replace(/\/[^/]*$/, '/') + r.file;
  out.innerHTML = `✓ Saved — <a href="${path}" target="_blank">${r.file}</a> (${fmtSize(r.size)})`;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async function post(action, data) {
  const fd = new FormData();
  Object.entries(data).forEach(([k,v]) => fd.append(k, v ?? ''));
  try {
    const r = await fetch(API(action), {method:'POST', body: fd});
    return await r.json();
  } catch(e) { return {ok: false, error: e.message}; }
}

function appendLog(id, msg, cls='info') {
  const el = document.getElementById(id);
  el.style.display = '';
  el.innerHTML += `<div class="log-line log-${cls}">${msg}</div>`;
}

function logLine(msg, cls, containerId) {
  const c = document.getElementById(containerId);
  if (!c) return;
  const d = document.createElement('div');
  d.className = 'log-line log-' + cls;
  d.textContent = msg;
  c.appendChild(d);
}

function fmtSize(b) {
  if (b >= 1073741824) return (b/1073741824).toFixed(2) + ' GB';
  if (b >= 1048576)    return (b/1048576).toFixed(2) + ' MB';
  if (b >= 1024)       return (b/1024).toFixed(2) + ' KB';
  return b + ' B';
}
function escHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function fmtTime(s) {
  if (!isFinite(s) || s < 0) return '…';
  if (s < 60) return Math.round(s) + 's';
  if (s < 3600) return Math.floor(s / 60) + 'm ' + Math.round(s % 60) + 's';
  return Math.floor(s / 3600) + 'h ' + Math.floor((s % 3600) / 60) + 'm';
}

init();
</script>
</body>
</html>
    <?php exit;
}
