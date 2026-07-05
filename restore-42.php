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

session_start();

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
    case 'download_backup':
        handleDownloadBackup();
        break;
    default:
        showHtml();
        break;
}

// ── Auth ─────────────────────────────────────────────────────────────────────

function isAuth(): bool
{
    return !empty($_SESSION['ra']);
}

function requireAuth(): void
{
    if (!isAuth()) {
        jsonErr('Not authenticated', 401);
    }
}

function handleLogin(): void
{
    $pw   = trim($_POST['password'] ?? '');
    $hash = STORED_PASS_HASH;

    if ($hash === '') {
        // First run: embed hash into own source
        if (strlen($pw) < 6) {
            jsonErr('Password must be at least 6 characters');
        }
        $newHash = password_hash($pw, PASSWORD_BCRYPT);
        $written = selfEmbedHash($newHash);
        $_SESSION['ra'] = true;
        jsonOk(['first_run' => true, 'self_written' => $written,
                'warn' => $written ? null : 'Could not write password into script file — make it writable by the web server (chmod 644).']);
    }

    if (password_verify($pw, $hash)) {
        $_SESSION['ra'] = true;
        jsonOk(['first_run' => false]);
    }
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
    session_destroy();
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
            jsonOk(['file' => $name, 'done' => true]);
        }
        jsonOk(['chunk' => $chunk, 'done' => false]);
    }

    move_uploaded_file($f['tmp_name'], $dest);
    jsonOk(['file' => $name, 'size' => filesize($dest), 'done' => true]);
}

function handleListFiles(): void
{
    $files = [];
    foreach (glob(UPLOADS_DIR . '/*') ?: [] as $f) {
        if (!is_file($f) || str_contains(basename($f), '.chunk')) {
            continue;
        }
        $files[] = ['name' => basename($f), 'size' => filesize($f), 'type' => detectUploadType($f)];
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
        $z->extractTo($dst);
        $z->close();
        return ['ok' => true];
    }
    exec('unzip ' . escapeshellarg($src) . ' -d ' . escapeshellarg($dst) . ' 2>&1', $o, $c);
    return $c === 0 ? ['ok' => true] : ['ok' => false, 'err' => implode("\n", $o)];
}

function extractTarGz(string $src, string $dst): array
{
    exec('tar -xzf ' . escapeshellarg($src) . ' -C ' . escapeshellarg($dst) . ' 2>&1', $o, $c);
    if ($c === 0) {
        return ['ok' => true];
    }
    // Try PharData
    try {
        (new PharData($src))->extractTo($dst, null, true);
        return ['ok' => true];
    } catch (Throwable $e) {
    }
    return ['ok' => false, 'err' => implode("\n", $o)];
}

function extractTar(string $src, string $dst): array
{
    exec('tar -xf ' . escapeshellarg($src) . ' -C ' . escapeshellarg($dst) . ' 2>&1', $o, $c);
    if ($c === 0) {
        return ['ok' => true];
    }
    try {
        (new PharData($src))->extractTo($dst, null, true);
        return ['ok' => true];
    } catch (Throwable $e) {
    }
    return ['ok' => false, 'err' => implode("\n", $o)];
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
    $fw     = detectFramework($root);
    $sqls   = findSqlFiles(EXTRACT_DIR);
    jsonOk(['root' => $root, 'nested' => $nested, 'framework' => $fw, 'sqls' => $sqls, 'files' => countFiles($root)]);
}

// ── Framework detection ───────────────────────────────────────────────────────

function detectFramework(string $dir): string
{
    if (is_dir($dir . '/bitrix') && file_exists($dir . '/bitrix/modules/main/include.php')) {
        return 'bitrix';
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

// ── SQL heuristics ────────────────────────────────────────────────────────────

function findSqlFiles(string $base): array
{
    $files = [];
    $it = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($base, FilesystemIterator::SKIP_DOTS));
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
    return new PDO($dsn, $user, $pass, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_TIMEOUT => 5]);
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
        jsonErr($e->getMessage());
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
    $rootDir = realpath($_POST['root_dir'] ?? '');
    if (!$rootDir) {
        jsonErr('Directory not found');
    }

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

function cfgBitrix(string $dir, array $c): array
{
    $res = [];
    $f   = $dir . '/bitrix/.settings.php';
    if (file_exists($f)) {
        $s = file_get_contents($f);
        $s = preg_replace("/'host'\s*=>\s*'[^']*'/", "'host' => '{$c['host']}'", $s);
        $s = preg_replace("/'login'\s*=>\s*'[^']*'/", "'login' => '{$c['user']}'", $s);
        $s = preg_replace("/'password'\s*=>\s*'[^']*'/", "'password' => '{$c['pass']}'", $s);
        $s = preg_replace("/'database'\s*=>\s*'[^']*'/", "'database' => '{$c['db']}'", $s);
        file_put_contents($f, $s);
        $res[] = "Updated .settings.php";
    }
    $f2 = $dir . '/bitrix/php_interface/dbconn.php';
    if (file_exists($f2)) {
        $s = file_get_contents($f2);
        $s = preg_replace('/\$DBHost\s*=\s*"[^"]*"/', "\$DBHost = \"{$c['host']}\"", $s);
        $s = preg_replace('/\$DBLogin\s*=\s*"[^"]*"/', "\$DBLogin = \"{$c['user']}\"", $s);
        $s = preg_replace('/\$DBPassword\s*=\s*"[^"]*"/', "\$DBPassword = \"{$c['pass']}\"", $s);
        $s = preg_replace('/\$DBName\s*=\s*"[^"]*"/', "\$DBName = \"{$c['db']}\"", $s);
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
    $s = file_get_contents($f);
    $map = ['DB_HOST' => $c['host'], 'DB_USER' => $c['user'], 'DB_PASSWORD' => $c['pass'], 'DB_NAME' => $c['db']];
    foreach ($map as $k => $v) {
        $s = preg_replace(
            "/define\s*\(\s*['\"]" . $k . "['\"]\s*,\s*['\"][^'\"]*['\"]\s*\)/",
            "define('{$k}', '{$v}')",
            $s
        );
    }
    if ($c['url']) {
        foreach (['WP_SITEURL', 'WP_HOME'] as $k) {
            if (str_contains($s, $k)) {
                $s = preg_replace(
                    "/define\s*\(\s*['\"]" . $k . "['\"]\s*,\s*['\"][^'\"]*['\"]\s*\)/",
                    "define('{$k}', '{$c['url']}')",
                    $s
                );
            }
        }
    }
    file_put_contents($f, $s);
    $res = ['Updated wp-config.php'];
    if ($c['url']) {
        $res[] = 'Also run: UPDATE wp_options SET option_value="' . $c['url'] . '" WHERE option_name IN ("siteurl","home")';
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
    $s = file_get_contents($f);
    $s = preg_replace("/\\\$database_server\s*=\s*'[^']*'/", "\$database_server = '{$c['host']}'", $s);
    $s = preg_replace("/\\\$database_user\s*=\s*'[^']*'/", "\$database_user = '{$c['user']}'", $s);
    $s = preg_replace("/\\\$database_password\s*=\s*'[^']*'/", "\$database_password = '{$c['pass']}'", $s);
    $s = preg_replace("/\\\$dbase\s*=\s*'[^']*'/", "\$dbase = '{$c['db']}'", $s);
    $s = preg_replace("/\\\$database_name\s*=\s*'[^']*'/", "\$database_name = '{$c['db']}'", $s);
    if ($c['url']) {
        $s = preg_replace("/\\\$site_url\s*=\s*'[^']*'/", "\$site_url = '{$c['url']}/'", $s);
        $s = preg_replace("/\\\$base_path\s*=\s*'[^']*'/", "\$base_path = '{$dir}/'", $s);
    }
    file_put_contents($f, $s);
    return ['Updated ' . basename($f)];
}

function cfgWebasyst(string $dir, array $c): array
{
    $res = [];
    $f = $dir . '/wa-config/db.php';
    if (file_exists($f)) {
        $s = file_get_contents($f);
        $s = preg_replace("/'host'\s*=>\s*'[^']*'/", "'host' => '{$c['host']}'", $s);
        $s = preg_replace("/'user'\s*=>\s*'[^']*'/", "'user' => '{$c['user']}'", $s);
        $s = preg_replace("/'password'\s*=>\s*'[^']*'/", "'password' => '{$c['pass']}'", $s);
        $s = preg_replace("/'database'\s*=>\s*'[^']*'/", "'database' => '{$c['db']}'", $s);
        file_put_contents($f, $s);
        $res[] = 'Updated wa-config/db.php';
    }
    if ($c['url']) {
        $f2 = $dir . '/wa-config/config.php';
        if (file_exists($f2)) {
            $s = file_get_contents($f2);
            $s = preg_replace("/'url'\s*=>\s*'[^']*'/", "'url' => '{$c['url']}'", $s);
            file_put_contents($f2, $s);
            $res[] = 'Updated wa-config/config.php';
        }
    }
    return $res ?: ['No Webasyst config files found'];
}

// ── Cache clearing ────────────────────────────────────────────────────────────

function handleClearCache(): void
{
    $fw  = $_POST['framework'] ?? '';
    $dir = realpath($_POST['root_dir'] ?? '');
    if (!$dir) {
        jsonErr('Directory not found');
    }

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
    $dir = realpath($_POST['root_dir'] ?? '');
    if (!$dir) {
        jsonErr('Directory not found');
    }

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

    // 2. Files archive
    $archive = $base . '.tar.gz';
    $excludes = ' --exclude=' . escapeshellarg(basename(WORK_DIR))
              . ' --exclude=' . escapeshellarg(basename(__FILE__));
    $tarCmd = "tar -czf " . escapeshellarg($archive) . $excludes .
              " -C " . escapeshellarg(dirname($rootDir)) . " " . escapeshellarg(basename($rootDir)) . " 2>&1";
    exec($tarCmd, $o, $ret);

    if ($ret === 0 && file_exists($archive)) {
        $sz = filesize($archive);
        if ($split > 0 && $sz > $split * 1048576) {
            $splitCmd = "split -b {$split}m " . escapeshellarg($archive) . " " . escapeshellarg($archive . '.') . " 2>&1";
            exec($splitCmd, $o2, $ret2);
            if ($ret2 === 0) {
                unlink($archive);
                $res[] = "Archive split into {$split}MB parts (Bitrix format)";
            } else {
                $res[] = "Archive: backup_{$ts}.tar.gz (" . fmtSize($sz) . ")";
            }
        } else {
            $res[] = "Archive: backup_{$ts}.tar.gz (" . fmtSize($sz) . ")";
        }
    } else {
        $res[] = "tar failed: " . implode(' ', $o);
    }

    // Collect files
    $files = [];
    foreach (glob($base . '*') as $f) {
        $files[] = ['name' => basename($f), 'size' => filesize($f)];
    }

    jsonOk(['results' => $res, 'files' => $files]);
}

// ── Utilities ─────────────────────────────────────────────────────────────────

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
      <div class="nav-item" onclick="showTab('backup')" id="tab-backup">
        <span class="icon">📦</span> Backup
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

async function doLogin() {
  const pw = document.getElementById('auth-pw').value;
  const r = await post('login', {password: pw});
  if (r.ok) { showApp(); }
  else { const el = document.getElementById('auth-err'); el.textContent = r.error; el.style.display = ''; }
}

async function doLogout() {
  await fetch(API('logout'));
  location.reload();
}

async function showApp() {
  document.getElementById('auth-screen').style.display = 'none';
  document.getElementById('main-app').style.display = '';
  renderStepsNav();
  showTab('restore');
  await loadFileList();
}

// ── Tabs ──────────────────────────────────────────────────────────────────────

function showTab(tab) {
  ['restore','backup'].forEach(t => {
    document.getElementById('pane-' + t).style.display = t === tab ? '' : 'none';
    document.getElementById('tab-' + t).classList.toggle('active', t === tab);
  });
  document.getElementById('topbar-title').textContent = tab === 'restore' ? 'Restore Wizard' : 'Create Backup';
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
  document.getElementById(`${pbId}-cancel`).onclick = () => { cancelled = true; ctrl?.abort(); };

  const started = Date.now();
  let bytesDone = 0;
  uploadsInProgress++;

  try { for (let c = 0; c < chunks; c++) {
    if (cancelled) break;
    ctrl = new AbortController();
    const fd = new FormData();
    fd.append('file', file.slice(c * CHUNK, (c+1) * CHUNK), file.name);
    fd.append('chunk', c); fd.append('chunks', chunks);
    let resp;
    try { resp = await fetch(API('upload'), {method:'POST', body: fd, signal: ctrl.signal}); }
    catch(e) {
      if (!cancelled) { failed = true; failReason = e.message || 'Network error'; }
      break;
    }
    if (!resp.ok) { failed = true; failReason = `Server error ${resp.status}`; break; }
    bytesDone += Math.min(CHUNK, file.size - c * CHUNK);
    const pct = Math.round((c + 1) / chunks * 100);
    const elapsed = (Date.now() - started) / 1000 || 0.001;
    const speed = bytesDone / elapsed;
    const left = (file.size - bytesDone) / speed;
    const pb = document.getElementById(pbId);
    const meta = document.getElementById(`${pbId}-meta`);
    if (pb) pb.style.width = pct + '%';
    if (meta) meta.textContent = `${pct}% · ${fmtSize(speed)}/s · ${fmtTime(left)} left`;
  } } finally { uploadsInProgress--; }

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
    if (meta) meta.textContent = `Done · ${fmtSize(file.size)} in ${fmtTime(total)}`;
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
    return `<li class="file-item">
      <span class="file-icon">${icon}</span>
      <div class="file-info">
        <div class="file-name">${f.name} ${badge}</div>
        <div class="file-meta">${fmtSize(f.size)}</div>
      </div>
      <button class="btn btn-secondary btn-sm" onclick="deleteFile('${f.name}')">✕</button>
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
