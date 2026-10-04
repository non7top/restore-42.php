<?php
/**
 * wr-util mini restore helper — the destination-side counterpart to
 * mini-backup.php/mini-download.php. Same deploy-time templating (random
 * filename, __WRU_TOKEN__ replaced before upload) — see wr-util's
 * miniScriptClient.ts.
 *
 * PHP 5.2/5.3-compatible syntax only, same reasoning as mini-backup.php.
 * Dispatched via ?action=: accept an uploaded file (archive or sql) into a
 * temp dir, fetch one directly from the source (see the "fetch" branch
 * below), extract+import previously uploaded files into this docroot, or
 * do a literal search/replace on a config file (see "fix_config" — the
 * caller supplies the exact old/new strings; no framework-specific
 * knowledge lives in this file itself).
 *
 * Two of the actions exist for restoring ONTO AN ALREADY-POPULATED SITE
 * (rerolling a live site back from a separately-upgraded copy, rather than
 * filling a freshly provisioned empty one): "drop_tables" empties the
 * database and "fs_snapshot" archives the docroot before wr-util wipes it.
 * Both take their own rollback copy first and refuse to proceed without one.
 */

// All __WRU_*__ placeholders are replaced at deploy time before upload —
// never committed with real values. DB credentials are baked in rather
// than passed as request params so they never land in the site's own
// plaintext HTTP access log.
$WRU_TOKEN = '__WRU_TOKEN__';
$WRU_DB_HOST = '__WRU_DB_HOST__';
$WRU_DB_PORT = '__WRU_DB_PORT__';
$WRU_DB_USER = '__WRU_DB_USER__';
$WRU_DB_PASS = '__WRU_DB_PASS__';
$WRU_DB_NAME = '__WRU_DB_NAME__';

/**
 * Deployment deadline (Unix seconds), baked in at deploy time.
 *
 * The token check used to be a bare string comparison with no time component,
 * so a helper stayed fully live until something deleted it. Orphans dated
 * 2026-07-30 and 2026-08-27 were found still answering five and six weeks
 * later, in live customer docroots, on servers with no packet filtering. An
 * expiry makes an abandoned helper go inert on its own instead of depending on
 * a sweep that may never run — final_sweep had never run for the migration
 * that left them.
 *
 * FAILS CLOSED: missing, non-numeric, or still the raw placeholder (i.e. this
 * file was copied rather than deployed) refuses everything.
 *
 * Duplicated VERBATIM in mini-backup.php, mini-download.php and
 * mini-restore.php — they are deployed independently and cannot share an
 * include. Keep the three copies identical.
 */
$WRU_DEADLINE = '__WRU_DEADLINE__';

/**
 * The ONE host `fetch` is allowed to pull from, baked in at deploy time.
 *
 * fetch shells out to curl against a caller-supplied URL. The filename it
 * writes was already constrained, but the URL host was not, so a valid token
 * bought a server-side request to anywhere the node could reach — including
 * things only it can reach. wr-util only ever points this at the source
 * site's own mini-download.php, so pinning the host costs nothing and removes
 * the whole class.
 *
 * Empty means fetch is disabled entirely, which is the right default for a
 * deployment that never needs it.
 */
$WRU_FETCH_HOST = '__WRU_FETCH_HOST__';

function wru_expired($deadline)
{
    if (!is_string($deadline) || !preg_match('/^[0-9]{1,11}$/', $deadline)) {
        return true;
    }
    return time() > (int) $deadline;
}

/**
 * The token, from a request HEADER or a POST body — never the query string.
 *
 * It used to be read from $_REQUEST, and the liveness ping sent it as
 * ?token=..., so a live credential was written into the site's plaintext HTTP
 * access log on every single call and then rotated into whatever archives that
 * log feeds. Same reasoning as the DB credentials above, which were already
 * baked in for exactly this reason.
 */
function wru_request_token()
{
    if (isset($_SERVER['HTTP_X_WRU_TOKEN'])) {
        return $_SERVER['HTTP_X_WRU_TOKEN'];
    }
    if (isset($_POST['token'])) {
        return $_POST['token'];
    }
    return '';
}

// See mini-backup.php's matching note: an inline PHP warning corrupts the JSON
// body and surfaces to the caller as an unparseable-response error that points
// nowhere near the real cause.
@ini_set('display_errors', '0');
@ini_set('html_errors', '0');

// ---------------------------------------------------------------------------
// json_encode/json_decode polyfill for PHP 5.1.
//
// The json_* functions arrived in PHP 5.2.0. legacy1.wr0.ru runs PHP 5.1.6
// (CentOS 5) where they are simply absent — and since every response in this
// file is JSON, the very first call was a fatal "Call to undefined function
// json_encode". The caller sees an unparseable body and reports "deployed
// mini-backup.php but couldn't get it to execute ... likely swallowed by the
// site's own .htaccess rewrite rules", which sends you looking at rewrite rules
// instead of at the PHP version. That misdiagnosis is the reason this is worth
// carrying rather than skipping the host.
//
// Measured on legacy1: PHP 5.1.6, json_encode absent, but exec() enabled with
// /bin/tar and /usr/bin/mysqldump present — the host can do the backup perfectly
// well once it can reply.
//
// Bytes >= 0x80 are escaped as \uXXXX treating each byte as Latin-1. These
// payloads carry filenames, byte counts and tool output, so the only loss is
// cosmetic mangling of a non-ASCII error string; it never affects control flow,
// and it guarantees the output is always valid JSON even when the host's own
// text is cp1251 rather than UTF-8.
if (!function_exists('json_encode')) {
    function wru_json_encode_value($v) {
        if (is_null($v)) { return 'null'; }
        if (is_bool($v)) { return $v ? 'true' : 'false'; }
        if (is_int($v) || is_float($v)) { return (string)$v; }
        if (is_array($v)) {
            $isList = true;
            $expect = 0;
            foreach ($v as $k => $ignored) {
                if ($k !== $expect) { $isList = false; break; }
                $expect++;
            }
            $parts = array();
            if ($isList) {
                foreach ($v as $item) { $parts[] = wru_json_encode_value($item); }
                return '[' . implode(',', $parts) . ']';
            }
            foreach ($v as $k => $item) {
                $parts[] = wru_json_encode_value((string)$k) . ':' . wru_json_encode_value($item);
            }
            return '{' . implode(',', $parts) . '}';
        }
        $s = (string)$v;
        $out = '"';
        $len = strlen($s);
        for ($i = 0; $i < $len; $i++) {
            $c = $s[$i];
            $o = ord($c);
            if ($c === '"') { $out .= '\\"'; }
            elseif ($c === '\\') { $out .= '\\\\'; }
            elseif ($c === "\n") { $out .= '\\n'; }
            elseif ($c === "\r") { $out .= '\\r'; }
            elseif ($c === "\t") { $out .= '\\t'; }
            elseif ($o < 0x20 || $o >= 0x80) { $out .= sprintf('\\u%04x', $o); }
            else { $out .= $c; }
        }
        return $out . '"';
    }
    function json_encode($v) { return wru_json_encode_value($v); }
}

// Deliberately only the shape these scripts actually decode: a flat JSON array
// of strings (the tar exclude list). Anything else returns null, which the one
// call site already handles by ignoring the excludes rather than failing.
if (!function_exists('json_decode')) {
    function json_decode($s, $assoc = false) {
        $s = trim($s);
        if ($s === '' || substr($s, 0, 1) !== '[' || substr($s, -1) !== ']') { return null; }
        $inner = trim(substr($s, 1, strlen($s) - 2));
        if ($inner === '') { return array(); }
        $out = array();
        $len = strlen($inner);
        $i = 0;
        while ($i < $len) {
            while ($i < $len && ($inner[$i] === ' ' || $inner[$i] === ',' || $inner[$i] === "\n")) { $i++; }
            if ($i >= $len) { break; }
            if ($inner[$i] !== '"') { return null; }
            $i++;
            $buf = '';
            while ($i < $len && $inner[$i] !== '"') {
                if ($inner[$i] === '\\' && $i + 1 < $len) {
                    $i++;
                    $e = $inner[$i];
                    if ($e === 'n') { $buf .= "\n"; }
                    elseif ($e === 'r') { $buf .= "\r"; }
                    elseif ($e === 't') { $buf .= "\t"; }
                    else { $buf .= $e; }
                } else {
                    $buf .= $inner[$i];
                }
                $i++;
            }
            $i++;
            $out[] = $buf;
        }
        return $out;
    }
}


header('Content-Type: application/json');

// Deadline first, before anything else answers — an expired helper is inert to
// every caller, liveness probes included.
if (wru_expired($WRU_DEADLINE)) {
    header('HTTP/1.1 410 Gone');
    echo json_encode(array('ok' => false, 'error' => 'this helper has expired; redeploy it'));
    exit;
}

// Liveness probe: carries NO token, and says nothing but "a helper is here and
// has not expired". wr-util uses it only to discover which domain and scheme
// actually reach this file, so target resolution no longer needs a credential
// in a URL. PHP_VERSION was dropped from the reply: an unauthenticated caller
// has no business being told it, and probePhpVersion answers that separately.
if (isset($_GET['ping'])) {
    echo json_encode(array('ok' => true, 'ping' => true));
    exit;
}

$token = wru_request_token();
if ($token === '' || $token !== $WRU_TOKEN) {
    header('HTTP/1.1 403 Forbidden');
    echo json_encode(array('ok' => false, 'error' => 'forbidden'));
    exit;
}

// Uploaded files live next to the script itself (__DIR__) so a simple
// relative path works regardless of where deployMiniScript's root->public
// ->files fallback placed it. Extraction target is a different matter:
// __DIR__ is wherever this script landed, NOT necessarily the site's real
// docroot (confirmed live on the sibling mini-backup.php: backing up
// __DIR__ instead of $_SERVER['DOCUMENT_ROOT'] silently archived only the
// subdirectory the script happened to sit in) — the extracted files must
// land at the real docroot.
// BOTH paths are resolved through realpath() before they are ever compared.
// ISPConfig serves each site from /var/www/<domain>/web, which is a SYMLINK to
// /var/www/clients/client<N>/web<N>/web — so DOCUMENT_ROOT and __DIR__ routinely
// name the SAME directory by two different strings. Comparing them raw is a
// silent, destructive bug: wipe_docroot decided nothing needed preserving,
// deleted its own staging directory, and destroyed a 718 MB transferred archive
// plus the pre-wipe rollback snapshot along with it. Confirmed live on
// madamsportik.ru, where __DIR__ was /var/www/clients/client20/web25/web and
// DOCUMENT_ROOT was /var/www/madamsportik.s20.wr0.ru/web.
$scriptDir = realpath(__DIR__);
if ($scriptDir === false) {
    $scriptDir = __DIR__;
}
$rawDocRoot = (isset($_SERVER['DOCUMENT_ROOT']) && $_SERVER['DOCUMENT_ROOT'] !== '') ? $_SERVER['DOCUMENT_ROOT'] : __DIR__;
$resolvedDocRoot = realpath($rawDocRoot);
$realDocRoot = rtrim(($resolvedDocRoot === false ? $rawDocRoot : $resolvedDocRoot), '/');
$uploadDirName = '.wru-restore';
$uploadDir = $scriptDir . '/' . $uploadDirName;
if (!is_dir($uploadDir)) {
    @mkdir($uploadDir, 0755, true);
}

/**
 * Resolves which client binary actually exists on this host.
 *
 * MariaDB 11 dropped the `mysql`/`mysqldump` compatibility symlinks in favour
 * of `mariadb`/`mariadb-dump` — confirmed on the mariadb:11 image, where
 * `mysql` is simply absent and every shell-out dies with "mysql: not found".
 * Older servers have only the mysql-named ones. Resolving instead of hardcoding
 * means one script works on both without knowing which server it landed on.
 * Falls back to the preferred name so a host with neither still fails with the
 * client's own message rather than a made-up one.
 */
function wruClientBinary($preferred, $alternate)
{
    foreach (array($preferred, $alternate) as $candidate) {
        $out = array();
        $code = 1;
        exec('command -v ' . escapeshellarg($candidate) . ' 2>/dev/null', $out, $code);
        if ($code === 0) {
            return $candidate;
        }
    }
    return $preferred;
}

/** Resolved once per request, then reused — see wruClientBinary. */
function wruMysqlBin()
{
    static $bin = null;
    if ($bin === null) {
        $bin = wruClientBinary('mysql', 'mariadb');
    }
    return $bin;
}

function wruMysqldumpBin()
{
    static $bin = null;
    if ($bin === null) {
        $bin = wruClientBinary('mysqldump', 'mariadb-dump');
    }
    return $bin;
}

/**
 * Ordered connection-argument candidates for the mysql/mysqldump clients.
 *
 * "localhost" is not one thing: to the MySQL/MariaDB CLIENT it usually means
 * the UNIX socket, but some client builds resolve it and open TCP to
 * 127.0.0.1 instead — and to the SERVER'S grant tables 'localhost' and
 * '127.0.0.1' are two different hosts. ISPConfig grants per-site users as
 * user@'localhost' only, so a client that quietly switches to TCP is refused
 * with "1130 - Host '127.0.0.1' is not allowed to connect". Confirmed live:
 * identical arguments worked on s12 and failed on s19.
 *
 * Socket first (matches how ISPConfig actually grants), TCP second (for a
 * genuinely remote or TCP-only server). A non-local host has no socket option
 * at all, so it gets TCP only.
 */
function wruMysqlConnAttempts($host, $port)
{
    $isLocal = ($host === '' || $host === 'localhost' || $host === '127.0.0.1' || $host === '::1');
    $tcpHost = $isLocal ? '127.0.0.1' : $host;
    $tcp = '--protocol=tcp -h ' . escapeshellarg($tcpHost) . ' -P ' . escapeshellarg($port);

    $attempts = array();
    // Socket first where it can exist: to MySQL a Unix socket counts as a secure
    // channel, which matters below.
    if ($isLocal) {
        $attempts['unix socket'] = '--protocol=socket';
    }
    $attempts['tcp ' . $tcpHost] = $tcp;
    // MySQL 8's default caching_sha2_password refuses to complete FULL
    // authentication over an unencrypted TCP connection. Confirmed live on
    // polimer-paket.ru's source: the socket was unavailable, the plain TCP
    // attempt reached the server and was refused with
    //   "2061: Authentication plugin 'caching_sha2_password' reported error:
    //    Authentication requires secure connection"
    // which is not a wrong password and not a missing grant — it is the
    // transport being unacceptable to the auth plugin. Two ways out, both tried:
    // fetch the server's RSA public key and encrypt the password with it, or
    // demand TLS for the whole connection.
    $attempts['tcp ' . $tcpHost . ' + server public key'] = $tcp . ' --get-server-public-key';
    $attempts['tcp ' . $tcpHost . ' + TLS'] = $tcp . ' --ssl-mode=REQUIRED';
    return $attempts;
}

/**
 * Is this client output a reason to try a DIFFERENT transport?
 *
 * Duplicated verbatim in mini-backup.php and mini-restore.php (deployed
 * independently, cannot share an include). Keep the copies identical.
 *
 * The gate exists so a real failure — bad SQL, a crashed table, a full disk —
 * is not retried, since it fails identically on every transport and retrying
 * would rewrite a half-finished dump. It listed three phrases and therefore
 * stopped dead on error 2061, which IS transport-dependent and would have
 * succeeded on the very next candidate.
 *
 * "unknown option"/"unknown variable" is included for the opposite reason: a
 * MariaDB client does not have --get-server-public-key or --ssl-mode, so that
 * candidate must be skipped rather than treated as a verdict about the database.
 */
function wruIsTransportError($text)
{
    $needles = array(
        'is not allowed to connect',
        'Access denied',
        "Can't connect",
        'Authentication requires secure connection',
        'caching_sha2_password',
        'Lost connection to MySQL server',
        'Unknown MySQL server host',
        'unknown option',
        'unknown variable',
    );
    foreach ($needles as $needle) {
        if (stripos($text, $needle) !== false) {
            return true;
        }
    }
    return false;
}

/**
 * Collects every symlink under $dir, recording its target verbatim. Twin of the
 * same function in mini-backup.php (each mini script is standalone by design —
 * they are uploaded individually and share no includes).
 *
 * Never recurses INTO a symlinked directory: on a multisite sister the target is
 * another site's tree, and following links invites cycles.
 */
function wruCollectSymlinks($dir, $base, &$out, $depth)
{
    if ($depth > 30 || count($out) >= 500) {
        return;
    }
    $entries = @scandir($dir);
    if ($entries === false) {
        return;
    }
    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $path = $dir . '/' . $entry;
        if (is_link($path)) {
            $target = @readlink($path);
            $resolved = @realpath($path);
            $out[] = array(
                'path' => ltrim(substr($path, strlen($base)), '/'),
                'target' => ($target === false) ? null : $target,
                'absolute' => ($target !== false && substr($target, 0, 1) === '/'),
                'resolved' => ($resolved === false) ? null : $resolved,
                'inside_docroot' => ($resolved !== false && strpos($resolved, $base . '/') === 0),
                'dangling' => !file_exists($path),
                'is_dir' => is_dir($path),
            );
            continue;
        }
        if (is_dir($path)) {
            wruCollectSymlinks($path, $base, $out, $depth + 1);
        }
    }
}

/**
 * Recursively deletes a path in pure PHP. Returns array(deletedCount, failures).
 *
 * No exec() and no shelling out, so this works on hosts where exec is disabled —
 * and scandir() enumerates dotfiles, so hidden files (.htaccess, .well-known and
 * the rest) are removed like anything else. A shell `rm -rf dir/*` would silently
 * skip exactly those.
 *
 * The is_link() test comes FIRST and deliberately: a symlink to a directory is
 * itself a directory as far as is_dir() is concerned, so recursing before
 * checking would follow it and delete the contents of whatever it points at —
 * potentially outside the docroot entirely. unlink() removes the link only.
 */
function wruRmTree($path, &$diag)
{
    if (is_link($path) || !is_dir($path)) {
        if (@unlink($path)) {
            return array(1, array());
        }
        // Removing a file needs write permission on its PARENT DIRECTORY, not on
        // the file itself, so a stubborn file is usually a directory-mode problem.
        // Worth one chmod-and-retry: it succeeds whenever this user owns the
        // directory, which is the common case for a tree the CMS itself wrote.
        @chmod(dirname($path), 0755);
        if (@unlink($path)) {
            return array(1, array());
        }
        if (count($diag) < 5) {
            $diag[] = wruPathDiag($path);
        }
        return array(0, array($path));
    }
    $deleted = 0;
    $failures = array();
    $entries = @scandir($path);
    if ($entries === false) {
        // Unreadable directory: chmod and retry, same reasoning as above.
        @chmod($path, 0755);
        $entries = @scandir($path);
        if ($entries === false) {
            if (count($diag) < 5) {
                $diag[] = wruPathDiag($path);
            }
            return array(0, array($path));
        }
    }
    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $r = wruRmTree($path . '/' . $entry, $diag);
        $deleted += $r[0];
        $failures = array_merge($failures, $r[1]);
    }
    if (@rmdir($path)) {
        return array($deleted + 1, $failures);
    }
    @chmod($path, 0755);
    if (@rmdir($path)) {
        return array($deleted + 1, $failures);
    }
    // A non-empty directory cannot be removed, so this is usually a CONSEQUENCE
    // of the failures already collected below it rather than a separate problem.
    if (count($failures) === 0 && count($diag) < 5) {
        $diag[] = wruPathDiag($path);
    }
    $failures[] = $path;
    return array($deleted, $failures);
}

/** Why a path could not be deleted, in facts rather than guesses: who owns it,
 * who owns its parent, what the modes are, and who this process is. Without
 * these the caller only learns THAT deletion failed. */
function wruPathDiag($path)
{
    $parent = dirname($path);
    $mode = @fileperms($path);
    $parentMode = @fileperms($parent);
    return array(
        'path' => $path,
        'is_dir' => is_dir($path),
        'mode' => ($mode === false) ? null : substr(sprintf('%o', $mode), -4),
        'owner_uid' => @fileowner($path),
        'group_gid' => @filegroup($path),
        'parent' => $parent,
        'parent_mode' => ($parentMode === false) ? null : substr(sprintf('%o', $parentMode), -4),
        'parent_owner_uid' => @fileowner($parent),
        'parent_writable' => @is_writable($parent),
        'process_uid' => function_exists('posix_geteuid') ? posix_geteuid() : null,
        'process_user' => @get_current_user(),
    );
}

/**
 * Backtick-quotes an identifier for a DDL statement. These names come from
 * SHOW FULL TABLES against this same database rather than from the caller, so
 * the doubling is for correctness on a name that legitimately contains a
 * backtick, not a sanitiser standing between a request param and the server.
 */
function wruBacktickQuote($name)
{
    return '`' . str_replace('`', '``', $name) . '`';
}

/**
 * Lists this database's tables and views via the first connection candidate
 * that authenticates (see wruMysqlConnAttempts for why there is more than
 * one). Returns array(label, conn, tables, views) on success, or a plain
 * string describing the failure — callers must check with is_array().
 */
function wruListTables($dbUser, $dbPass, $dbName, $attempts, $tmpPath)
{
    $errPath = $tmpPath . '.err';
    $lastErr = 'no connection candidates';
    foreach ($attempts as $label => $connArgs) {
        // -N: no column headers, -B: tab-separated — two columns, the table
        // name and its type ("BASE TABLE" or "VIEW"), which is why this uses
        // SHOW FULL TABLES rather than SHOW TABLES. A view has to be dropped
        // with DROP VIEW, not DROP TABLE.
        $cmd = 'MYSQL_PWD=' . escapeshellarg($dbPass) . ' ' . wruMysqlBin() . ' --default-character-set=binary ' . $connArgs .
            ' -N -B -e ' . escapeshellarg('SHOW FULL TABLES') .
            ' -u ' . escapeshellarg($dbUser) . ' ' . escapeshellarg($dbName) .
            ' > ' . escapeshellarg($tmpPath) . ' 2>' . escapeshellarg($errPath);
        $code = 0;
        exec($cmd, $dummy, $code);
        $raw = @file_get_contents($errPath);
        $err = ($raw === false) ? '' : trim($raw);
        @unlink($errPath);
        if ($code === 0) {
            $tables = array();
            $views = array();
            $lines = @file($tmpPath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            @unlink($tmpPath);
            if ($lines === false) {
                $lines = array();
            }
            foreach ($lines as $line) {
                $parts = explode("\t", $line);
                if (!isset($parts[0]) || $parts[0] === '') {
                    continue;
                }
                $type = isset($parts[1]) ? strtoupper(trim($parts[1])) : 'BASE TABLE';
                if ($type === 'VIEW') {
                    $views[] = $parts[0];
                } else {
                    $tables[] = $parts[0];
                }
            }
            return array('label' => $label, 'conn' => $connArgs, 'tables' => $tables, 'views' => $views);
        }
        @unlink($tmpPath);
        $lastErr = 'via ' . $label . ': ' . $err;
        // Same retry gate as the SQL import: only a connection-level refusal
        // could succeed over the other transport. Anything else (no such
        // database, no SELECT grant) fails identically both ways.
        if (!wruIsTransportError($err)) {
            return 'SHOW FULL TABLES failed ' . $lastErr;
        }
    }
    return 'could not connect on any transport (' . $lastErr . ')';
}

$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : '';

// Pulls a backup file directly from the source's mini-download.php (server
// to server) instead of having it routed through wr-util's own process as
// an HTTP multipart upload — confirmed live that a large (467MB) upload
// fails outright, almost certainly PHP's own default upload_max_filesize/
// post_max_size limits (typically 2-8MB) rejecting it. A direct fetch has
// no such limit and skips an unnecessary double-hop.
/** How to feed a staged archive to tar.
 *
 * $archiveName is the logical name (wru-backup-<ts>.tar.gz). The backup is
 * normally staged as parts, name.tar.gz.000, .001, ...; a host whose split could
 * not number its output stages the single file. Returns the shell text to put
 * before tar and the argument for tar -f, or null with $error set. A gap in the
 * numbering is refused here: the shell glob would skip the missing part and tar
 * would fail much later, in the middle of a half-extracted docroot. */
function wruArchiveSource($uploadDir, $archiveName, &$error)
{
    $base = $uploadDir . '/' . $archiveName;
    if (is_file($base)) {
        return array('prefix' => '', 'file' => escapeshellarg($base));
    }
    $parts = @glob($base . '.[0-9][0-9][0-9]');
    if (!is_array($parts) || count($parts) === 0) {
        $error = 'archive not found: ' . $archiveName;
        return null;
    }
    sort($parts);
    foreach ($parts as $i => $partPath) {
        if (substr($partPath, -3) !== sprintf('%03d', $i)) {
            $error = 'archive part ' . sprintf('%03d', $i) . ' is missing (found ' . basename($partPath) . ' in its place)';
            return null;
        }
    }
    return array('prefix' => 'cat ' . escapeshellarg($base) . '.[0-9][0-9][0-9] | ', 'file' => '-');
}

if ($action === 'fetch') {
    if (!function_exists('exec')) {
        echo json_encode(array('ok' => false, 'error' => 'exec() is disabled on this host — cannot shell out to curl'));
        exit;
    }
    $url = isset($_POST['url']) ? $_POST['url'] : '';
    $name = isset($_POST['name']) ? basename($_POST['name']) : '';
    if (!preg_match('/^wru-backup-[0-9]{14}\.(tar\.gz(\.[0-9]{3})?|sql)$/', $name)) {
        echo json_encode(array('ok' => false, 'error' => 'invalid destination filename'));
        exit;
    }
    // Only ever fetches from a URL wr-util itself constructed (the source's
    // own mini-download.php, whose token is unrelated to this script's) —
    // still worth a basic scheme check since this shells out.
    if (strpos($url, 'http://') !== 0 && strpos($url, 'https://') !== 0) {
        echo json_encode(array('ok' => false, 'error' => 'invalid url'));
        exit;
    }
    // ...and the host must be the one baked in at deploy time. Without this a
    // valid token bought an arbitrary server-side request from inside the
    // customer's network.
    if ($WRU_FETCH_HOST === '' || preg_match('/^__WRU_/', $WRU_FETCH_HOST)) {
        echo json_encode(array('ok' => false, 'error' => 'fetch is not enabled on this deployment'));
        exit;
    }
    $urlHost = parse_url($url, PHP_URL_HOST);
    if (!is_string($urlHost) || strtolower($urlHost) !== strtolower($WRU_FETCH_HOST)) {
        echo json_encode(array('ok' => false, 'error' => 'url host is not the host this helper may fetch from'));
        exit;
    }
    // The source helper now wants its token in a header, and a header on the
    // curl COMMAND LINE would be readable by any local user via `ps` for the
    // whole transfer — the same trap mysqldump --defaults-file avoids a few
    // hundred lines below. So it goes in a 0600 curl config file instead.
    // Strictly shaped, because this string is written into that config.
    $authHeader = isset($_POST['auth_header']) ? $_POST['auth_header'] : '';
    if ($authHeader !== '' && !preg_match('/^X-WRU-Token: [0-9a-f]{16,64}$/', $authHeader)) {
        echo json_encode(array('ok' => false, 'error' => 'malformed auth_header'));
        exit;
    }
    $curlCfg = '';
    if ($authHeader !== '') {
        $curlCfg = tempnam(sys_get_temp_dir(), 'wru');
        if ($curlCfg === false) {
            echo json_encode(array('ok' => false, 'error' => 'could not create a curl config file'));
            exit;
        }
        @chmod($curlCfg, 0600);
        file_put_contents($curlCfg, 'header = "' . $authHeader . '"' . "\n");
    }
    $dest = $uploadDir . '/' . $name;
    // -L: without it, curl doesn't follow redirects at all — -f alone only
    // catches 4xx/5xx, so a 3xx response (e.g. the source site's own
    // canonical-domain/HTTPS-enforcing .htaccess redirect, hit because
    // this fetches via the source's auto-generated service domain, not
    // its real one) gets silently saved as the "downloaded" file, curl
    // still exits 0, and this reports success on a corrupt (HTML, not
    // tar/sql) download. Confirmed live: exactly this happened.
    // -C -: resume an interrupted transfer instead of starting over.
    //
    // Multi-GB archives do not survive a single request here. The web server
    // layer (php-fpm request_terminate_timeout / nginx fastcgi_read_timeout)
    // kills the request long before PHP's own max_execution_time, and the
    // caller sees an HTML error page instead of JSON. Confirmed live on a 7.1GB
    // archive: 5.2GB had landed when the request was killed, and without -C -
    // the next attempt would have discarded all of it and begun again.
    // With resume, each call continues where the last stopped, so repeated
    // calls converge -- see wr-util's transferBackup, which loops on this.
    // A request the web server killed does not kill the curl it started, so a
    // retry can find the previous transfer still writing. Two curls appending to
    // one file leave it longer than the source and corrupt (12565852864 bytes
    // for a 12565639872-byte archive). If the file is still growing, say so and
    // let the caller wait.
    if (isset($_POST['restart']) && $_POST['restart'] === '1') {
        @unlink($dest);
    } elseif (is_file($dest)) {
        clearstatcache();
        $sizeA = filesize($dest);
        sleep(3);
        clearstatcache();
        $sizeB = filesize($dest);
        if ($sizeB !== $sizeA) {
            if ($curlCfg !== '') {
                @unlink($curlCfg);
            }
            echo json_encode(array('ok' => false, 'busy' => true, 'size' => $sizeB, 'output' => 'a previous fetch is still writing this file'));
            exit;
        }
    }
    $before = is_file($dest) ? filesize($dest) : 0;
    $fetchCmd = 'curl -sS -f -L -C - ';
    if ($curlCfg !== '') {
        $fetchCmd .= '-K ' . escapeshellarg($curlCfg) . ' ';
    }
    $fetchCmd .= '-o ' . escapeshellarg($dest) . ' ' . escapeshellarg($url) . ' 2>&1';
    $fetchOut = array();
    $fetchCode = 0;
    exec($fetchCmd, $fetchOut, $fetchCode);
    if ($curlCfg !== '') {
        @unlink($curlCfg);
    }
    $after = is_file($dest) ? filesize($dest) : 0;
    $ok = ($fetchCode === 0) && $after > 0;
    echo json_encode(array(
        'ok' => $ok,
        'name' => $ok ? $name : null,
        // Always report the size, success or not: a partial transfer is
        // progress, and the caller needs it to decide whether to resume.
        'size' => $after,
        'bytes_added' => $after - $before,
        'resumed_from' => $before,
        'curl_exit' => $fetchCode,
        'output' => implode("\n", $fetchOut),
    ));
    exit;
}

if ($action === 'upload') {
    if (!isset($_FILES['file']) || $_FILES['file']['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(array('ok' => false, 'error' => 'no file uploaded'));
        exit;
    }
    $name = isset($_POST['name']) ? basename($_POST['name']) : basename($_FILES['file']['name']);
    if (!preg_match('/^wru-backup-[0-9]{14}\.(tar\.gz(\.[0-9]{3})?|sql)$/', $name)) {
        echo json_encode(array('ok' => false, 'error' => 'invalid destination filename'));
        exit;
    }
    $dest = $uploadDir . '/' . $name;
    if (!move_uploaded_file($_FILES['file']['tmp_name'], $dest)) {
        echo json_encode(array('ok' => false, 'error' => 'move_uploaded_file failed'));
        exit;
    }
    echo json_encode(array('ok' => true, 'name' => $name, 'size' => filesize($dest)));
    exit;
}

/**
 * Detached extraction, for archives too big to unpack inside one request.
 *
 * The synchronous path below is fine for modest archives, but the web server in
 * front of PHP (php-fpm request_terminate_timeout / nginx fastcgi_read_timeout)
 * kills a long request regardless of max_execution_time -- proven here when a
 * 7.1GB fetch died mid-transfer and returned HTML. An extraction killed the same
 * way is worse than a failed download: it leaves a half-populated docroot with
 * nothing recording how far it got. So tar runs under nohup, outliving the
 * request, and the caller polls extract_status.
 */
if ($action === 'extract_start') {
    if (!function_exists('shell_exec')) {
        echo json_encode(array('ok' => false, 'error' => 'shell_exec() is disabled — cannot detach tar'));
        exit;
    }
    $archiveName = isset($_POST['archive']) ? basename($_POST['archive']) : '';
    if (!preg_match('/^wru-backup-[0-9]{14}\.tar\.gz$/', $archiveName)) {
        echo json_encode(array('ok' => false, 'error' => 'invalid archive filename'));
        exit;
    }
    $archiveError = '';
    $archiveSrc = wruArchiveSource($uploadDir, $archiveName, $archiveError);
    if ($archiveSrc === null) {
        echo json_encode(array('ok' => false, 'error' => $archiveError));
        exit;
    }
    $log = $uploadDir . '/.wru-extract.log';
    $pidf = $uploadDir . '/.wru-extract.pid';
    $done = $uploadDir . '/.wru-extract.done';
    @unlink($log);
    @unlink($done);
    // The exit status is written to a marker file after tar finishes: once the
    // process is gone there is no other way to tell success from failure.
    $cmd = 'nohup sh -c ' . escapeshellarg(
    // The docroot's own .htaccess is extracted UNDER A DIFFERENT NAME, not placed
    // and not discarded: it lands as .htaccess.restore, which is the same
    // arrangement Bitrix's own restore uses.
    //
    // It must not be placed, because the archive's copy carries the SOURCE site's
    // rules: its canonical hostname, and on this fleet a scheme-forcing rule that
    // loops forever, since nginx terminates TLS and proxies to Apache on
    // 127.0.0.1:82 where mod_rewrite's %{HTTPS} is never "on". Placing it also
    // routes unknown paths into bitrix/urlrewrite.php, which swallows THIS script
    // and is why the post-restore config rewrite could not be reached on souz98,
    // ragranat, lkristall and rhp2.
    //
    // It must not be discarded either: it is usually the only record of the site's
    // real configuration -- canonical-host redirects, per-section rules, error
    // documents -- and the operator needs to read it and copy back what applies.
    //
    // --transform is ANCHORED to the docroot root. Nested .htaccess files are
    // extracted normally and must be: upload/.htaccess is what stops PHP
    // executing out of the uploads directory, so dropping it would be a security
    // regression rather than a tidy-up.
    //
    // The archive's own .htaccess.restore is excluded to keep the destination name
    // unambiguous. Without that, two members would extract to the same path and
    // whichever tar wrote last would win -- and if that were the archive's stock
    // .htaccess.restore, the site's real rules would be silently lost.
        $archiveSrc['prefix'] . 'tar -xzf ' . $archiveSrc['file'] . ' ' . ' --transform=' . escapeshellarg('s|^\./\.htaccess$|./.htaccess.restore|') . ' --exclude=./.htaccess.restore ' . ' -C ' . escapeshellarg($realDocRoot)
        . ' > ' . escapeshellarg($log) . ' 2>&1; echo $? > ' . escapeshellarg($done)
    ) . ' > /dev/null 2>&1 & echo $!';
    $pid = trim(shell_exec($cmd));
    @file_put_contents($pidf, $pid);
    echo json_encode(array('ok' => true, 'pid' => $pid, 'archive' => $archiveName));
    exit;
}

if ($action === 'extract_status') {
    $log = $uploadDir . '/.wru-extract.log';
    $pidf = $uploadDir . '/.wru-extract.pid';
    $done = $uploadDir . '/.wru-extract.done';
    $pid = is_file($pidf) ? trim(file_get_contents($pidf)) : '';
    $running = false;
    if ($pid !== '' && function_exists('exec')) {
        $psOut = array();
        $psCode = 0;
        exec('ps -p ' . escapeshellarg($pid) . ' -o pid=', $psOut, $psCode);
        $running = ($psCode === 0 && count($psOut) > 0);
    }
    $exit = is_file($done) ? (int)trim(file_get_contents($done)) : null;
    // Entry count as a coarse progress signal — cheap next to du on a big tree.
    $entries = 0;
    if (function_exists('exec')) {
        $cntOut = array();
        exec('find ' . escapeshellarg($realDocRoot) . ' | wc -l', $cntOut);
        $entries = isset($cntOut[0]) ? (int) trim($cntOut[0]) : 0;
    }
    echo json_encode(array(
        'ok' => true,
        'running' => $running,
        'finished' => ($exit !== null),
        'exit_code' => $exit,
        'entries' => $entries,
        'output' => is_file($log) ? substr((string) file_get_contents($log), 0, 4000) : '',
    ));
    exit;
}

if ($action === 'restore') {
    if (!function_exists('exec')) {
        echo json_encode(array('ok' => false, 'error' => 'exec() is disabled on this host — cannot shell out to tar/mysql'));
        exit;
    }

    $archiveName = isset($_POST['archive']) ? basename($_POST['archive']) : '';
    $sqlName = isset($_POST['sql']) ? basename($_POST['sql']) : '';

    $results = array();
    $ok = true;

    if ($archiveName !== '') {
        if (!preg_match('/^wru-backup-[0-9]{14}\.tar\.gz$/', $archiveName)) {
            echo json_encode(array('ok' => false, 'error' => 'invalid archive filename'));
            exit;
        }
        $archiveError = '';
        $archiveSrc = wruArchiveSource($uploadDir, $archiveName, $archiveError);
        if ($archiveSrc === null) {
            echo json_encode(array('ok' => false, 'error' => $archiveError));
            exit;
        }
        // Same anchored rename as the detached path above; see the comment there.
        $extractCmd = $archiveSrc['prefix'] . 'tar -xzf ' . $archiveSrc['file'] . ' ' . ' --transform=' . escapeshellarg('s|^\./\.htaccess$|./.htaccess.restore|') . ' --exclude=./.htaccess.restore ' . ' -C ' . escapeshellarg($realDocRoot) . ' 2>&1';
        $extractOut = array();
        $extractCode = 0;
        exec($extractCmd, $extractOut, $extractCode);
        $results[] = implode("\n", $extractOut);
        $ok = $ok && ($extractCode === 0);
    }

    if ($sqlName !== '') {
        if (!preg_match('/^wru-backup-[0-9]{14}\.sql$/', $sqlName)) {
            echo json_encode(array('ok' => false, 'error' => 'invalid sql filename'));
            exit;
        }
        $sqlPath = $uploadDir . '/' . $sqlName;
        if (!is_file($sqlPath)) {
            echo json_encode(array('ok' => false, 'error' => 'sql file not found: ' . $sqlName));
            exit;
        }
        $dbHost = $WRU_DB_HOST !== '' ? $WRU_DB_HOST : 'localhost';
        $dbPort = $WRU_DB_PORT !== '' ? $WRU_DB_PORT : '3306';
        $dbUser = $WRU_DB_USER;
        $dbPass = $WRU_DB_PASS;
        $dbName = $WRU_DB_NAME;
        // --default-character-set=binary MUST match how mini-backup.php wrote
        // the dump (byte-exact, no SET NAMES header — see its comment). With
        // the header absent, the client would otherwise fall back to its own
        // default charset and reinterpret every stored byte, corrupting text
        // on a non-UTF-8 site. MYSQL_PWD rather than -p so the password isn't
        // visible in `ps` for the length of the import.
        //
        // Connection is attempted over the UNIX SOCKET FIRST, then TCP.
        // Confirmed live on s19: "-h localhost -P 3306" made the client open a
        // TCP connection anyway, and the server refused it with
        //   1130 - Host '127.0.0.1' is not allowed to connect to this MariaDB server
        // because ISPConfig grants its per-site users as user@'localhost',
        // which in MySQL/MariaDB means the socket, NOT 127.0.0.1 — they are
        // distinct hosts in the grant tables. The same command worked on the
        // older MariaDB on s12, so this varies by client version and cannot be
        // assumed either way. Trying socket then TCP covers both without
        // needing to know which server is which.
        $attempts = wruMysqlConnAttempts($dbHost, $dbPort);
        $importCode = 1;
        $errContents = '';
        foreach ($attempts as $label => $connArgs) {
            $importCmd = 'MYSQL_PWD=' . escapeshellarg($dbPass) . ' ' . wruMysqlBin() . ' --default-character-set=binary ' . $connArgs .
                ' -u ' . escapeshellarg($dbUser) .
                ' ' . escapeshellarg($dbName) .
                ' < ' . escapeshellarg($sqlPath) . ' 2>' . escapeshellarg($sqlPath . '.err');
            $importCode = 0;
            exec($importCmd, $dummy, $importCode);
            $raw = @file_get_contents($sqlPath . '.err');
            $errContents = ($raw === false) ? '' : trim($raw);
            @unlink($sqlPath . '.err');
            if ($importCode === 0) {
                $results[] = 'imported via ' . $label;
                break;
            }
            $results[] = 'connection attempt via ' . $label . ' failed: ' . $errContents;
            // Only a connection-level refusal is worth retrying differently.
            // Anything else (bad SQL, missing table, disk full) will fail the
            // same way on the other transport, and retrying would just import
            // half the dump twice.
            if (!wruIsTransportError($errContents)) {
                break;
            }
        }
        $ok = $ok && ($importCode === 0);
    }

    echo json_encode(array('ok' => $ok, 'results' => $results));
    exit;
}

/**
 * Drops every table and view in this site's database.
 *
 * Restoring into an already-populated database is NOT a replacement: the dump
 * mini-backup.php writes carries DROP TABLE IF EXISTS + CREATE per dumped
 * table (that is what --opt/--add-drop-table gives you), so every table the
 * dump does not happen to mention survives the import untouched. Rerolling a
 * live site from a separately-upgraded copy is precisely the case where that
 * bites: the two schemas disagree about which tables exist, and the ones only
 * the old schema had would sit there afterwards looking like live data.
 *
 * Dumps the current contents to .wru-restore/wru-predrop-<ts>.sql FIRST and
 * refuses to drop anything at all if that dump fails — this runs against
 * production data whose only other copy may be the site itself.
 *
 * Tables and views only. mysqldump's --routines/--events (each with their own
 * DROP IF EXISTS) replace a routine/event that exists on both sides, but one
 * that exists only on the destination survives -- this step doesn't drop
 * those first. Triggers go with their tables either way.
 */
/**
 * Read-only credential test. Connects with the credentials baked into THIS
 * script and reports which connection path authenticated, plus what it found.
 * Touches nothing.
 *
 * Exists because "are the destination's database credentials actually usable"
 * was, until now, only ever answered as a side effect of a step that also
 * changed something -- an import, or a drop. When they failed, the failure
 * surfaced as a confusing secondary symptom: a restore reporting failure after
 * having already imported, a site 500ing with "Access denied for user
 * '<source user>'", a wipe refusing over a name mismatch. Confirmed live on
 * rhp2: the credentials ISPConfig held hashed to exactly what this script
 * carried, while the live MySQL account had a third, unrelated hash -- and
 * establishing that took a long detour through the wrong conclusions.
 *
 * The password is never echoed back; only its length, because "wrong password"
 * and "no password" are different failures.
 */
/**
 * Read-only credential test. Connects with the credentials baked into THIS
 * script and reports which connection path authenticated, plus what it found.
 * Changes nothing.
 *
 * Exists because "are the destination's database credentials actually usable"
 * used to be answerable only as a side effect of a step that also CHANGED
 * something - an import, or a drop. When the credentials were wrong the failure
 * surfaced as a confusing secondary symptom: a restore reporting failure after
 * it had already imported, the site returning 500 "Access denied for user
 * '<source user>'", a wipe refusing over a name mismatch.
 *
 * Confirmed live on rhp2: the password ISPConfig held hashed to exactly what
 * this script carried, while the live MySQL account had a third, unrelated
 * hash. Establishing that took a long detour through wrong conclusions, all of
 * which one read-only connection test would have settled immediately.
 *
 * The password is never echoed back, only its length: "wrong password" and "no
 * password at all" are different failures and the operator has to tell them
 * apart.
 */
if ($action === 'db_check') {
    if (!function_exists('exec')) {
        echo json_encode(array('ok' => false, 'error' => 'exec() is disabled on this host - cannot shell out to mysql'));
        exit;
    }
    $dbHost = $WRU_DB_HOST !== '' ? $WRU_DB_HOST : 'localhost';
    $dbPort = $WRU_DB_PORT !== '' ? $WRU_DB_PORT : '3306';
    if ($WRU_DB_NAME === '' || $WRU_DB_USER === '') {
        echo json_encode(array('ok' => false, 'error' => 'no database credentials were baked into this script at deploy time'));
        exit;
    }
    $attempts = wruMysqlConnAttempts($dbHost, $dbPort);
    $listed = wruListTables($WRU_DB_USER, $WRU_DB_PASS, $WRU_DB_NAME, $attempts, $uploadDir . '/.wru-dbcheck');
    if (!is_array($listed)) {
        echo json_encode(array(
            'ok' => false,
            'database' => $WRU_DB_NAME,
            'user' => $WRU_DB_USER,
            'pass_len' => strlen($WRU_DB_PASS),
            'tried' => implode(', ', array_keys($attempts)),
            'error' => $listed,
        ));
        exit;
    }
    echo json_encode(array(
        'ok' => true,
        'database' => $WRU_DB_NAME,
        'user' => $WRU_DB_USER,
        'pass_len' => strlen($WRU_DB_PASS),
        'connected_via' => $listed['label'],
        'tables' => count($listed['tables']),
        'views' => count($listed['views']),
    ));
    exit;
}

if ($action === 'drop_tables') {
    if (!function_exists('exec')) {
        echo json_encode(array('ok' => false, 'error' => 'exec() is disabled on this host — cannot shell out to mysql'));
        exit;
    }
    $dbHost = $WRU_DB_HOST !== '' ? $WRU_DB_HOST : 'localhost';
    $dbPort = $WRU_DB_PORT !== '' ? $WRU_DB_PORT : '3306';
    $dbUser = $WRU_DB_USER;
    $dbPass = $WRU_DB_PASS;
    $dbName = $WRU_DB_NAME;
    if ($dbName === '' || $dbUser === '') {
        echo json_encode(array('ok' => false, 'error' => 'no database credentials were baked into this script at deploy time'));
        exit;
    }

    $attempts = wruMysqlConnAttempts($dbHost, $dbPort);
    $listed = wruListTables($dbUser, $dbPass, $dbName, $attempts, $uploadDir . '/.wru-tables');
    if (!is_array($listed)) {
        echo json_encode(array('ok' => false, 'error' => $listed));
        exit;
    }
    $tables = $listed['tables'];
    $views = $listed['views'];
    if (count($tables) === 0 && count($views) === 0) {
        echo json_encode(array(
            'ok' => true,
            'database' => $dbName,
            'via' => $listed['label'],
            'client' => wruMysqlBin(),
            'dropped_tables' => 0,
            'dropped_views' => 0,
            'remaining' => 0,
            'backup' => null,
            'note' => 'database was already empty — nothing to drop',
        ));
        exit;
    }

    $backup = null;
    if (!isset($_POST['skip_backup']) || $_POST['skip_backup'] !== '1') {
        $backupName = 'wru-predrop-' . gmdate('YmdHis') . '.sql';
        $backupPath = $uploadDir . '/' . $backupName;
        $dumpErrPath = $backupPath . '.err';
        // Same charset flags as mini-backup.php's dump, for the same reason:
        // a byte-exact round trip on a database that isn't UTF-8.
        $dumpCmd = 'MYSQL_PWD=' . escapeshellarg($dbPass) . ' ' . wruMysqldumpBin() . ' --opt --no-tablespaces' .
            ' --default-character-set=binary --skip-set-charset ' . $listed['conn'] .
            ' -u ' . escapeshellarg($dbUser) . ' ' . escapeshellarg($dbName) .
            ' > ' . escapeshellarg($backupPath) . ' 2>' . escapeshellarg($dumpErrPath);
        $dumpCode = 0;
        exec($dumpCmd, $dummy, $dumpCode);
        $raw = @file_get_contents($dumpErrPath);
        $dumpErr = ($raw === false) ? '' : trim($raw);
        @unlink($dumpErrPath);
        $dumpSize = is_file($backupPath) ? filesize($backupPath) : 0;
        if ($dumpCode !== 0 || $dumpSize === 0) {
            echo json_encode(array(
                'ok' => false,
                'error' => 'refusing to drop anything: the pre-drop backup failed (mysqldump exit ' . $dumpCode .
                    ', ' . $dumpSize . ' bytes)' . ($dumpErr !== '' ? ': ' . $dumpErr : ''),
            ));
            exit;
        }
        // A dumped VIEW (or routine) carries a DEFINER=`user`@`host` clause, and
        // recreating it requires the SET USER privilege unless that definer IS
        // the importing user. This dump exists purely to be re-imported BY THE
        // SITE USER, so any definer naming someone else makes the rollback
        // unusable at the moment it is needed. Confirmed in a container: a
        // root-defined view failed with
        //   ERROR 1227 (42000): Access denied; you need (at least one of) the
        //   SET USER privilege(s) for this operation
        // and the import stopped there, leaving the rollback half-applied.
        //
        // Rewritten only when a DEFINER is actually present, so the ordinary
        // case (a schema of plain tables) does no extra pass over what may be a
        // very large file and never needs sed's temporary second copy on disk.
        $definerNote = null;
        $grepCode = 1;
        exec('grep -q ' . escapeshellarg('DEFINER=') . ' ' . escapeshellarg($backupPath) . ' 2>/dev/null', $dummy, $grepCode);
        if ($grepCode === 0) {
            $sedCode = 0;
            exec('sed -i -e ' . escapeshellarg('s/DEFINER=[^ ]*@[^ ]* //g') .
                ' -e ' . escapeshellarg('s/SQL SECURITY DEFINER/SQL SECURITY INVOKER/g') .
                ' ' . escapeshellarg($backupPath) . ' 2>/dev/null', $dummy, $sedCode);
            if ($sedCode === 0) {
                $definerNote = 'DEFINER clauses rewritten to the invoker so the site user can re-import this';
                $dumpSize = is_file($backupPath) ? filesize($backupPath) : $dumpSize;
            } else {
                $definerNote = 'WARNING: this dump carries DEFINER clauses that could not be rewritten' .
                    ' (sed exit ' . $sedCode . ') — re-importing it may need SET USER privileges';
            }
        }
        $backup = array('name' => $backupName, 'size' => $dumpSize, 'definers' => $definerNote);
    }

    $dropPath = $uploadDir . '/.wru-drop.sql';
    $sql = "SET FOREIGN_KEY_CHECKS=0;\n";
    // Chunked rather than one statement per object: a single DROP naming every
    // table is one very long line, and a large enough schema would run into
    // max_allowed_packet. Chunked also keeps the whole thing to a handful of
    // round trips instead of one per table.
    $viewChunks = array_chunk($views, 50);
    foreach ($viewChunks as $chunk) {
        $sql .= 'DROP VIEW IF EXISTS ' . implode(',', array_map('wruBacktickQuote', $chunk)) . ";\n";
    }
    $tableChunks = array_chunk($tables, 50);
    foreach ($tableChunks as $chunk) {
        $sql .= 'DROP TABLE IF EXISTS ' . implode(',', array_map('wruBacktickQuote', $chunk)) . ";\n";
    }
    $sql .= "SET FOREIGN_KEY_CHECKS=1;\n";
    if (@file_put_contents($dropPath, $sql) === false) {
        echo json_encode(array('ok' => false, 'error' => 'could not write the DROP script to ' . $dropPath));
        exit;
    }
    $dropErrPath = $dropPath . '.err';
    $dropCmd = 'MYSQL_PWD=' . escapeshellarg($dbPass) . ' ' . wruMysqlBin() . ' --default-character-set=binary ' . $listed['conn'] .
        ' -u ' . escapeshellarg($dbUser) . ' ' . escapeshellarg($dbName) .
        ' < ' . escapeshellarg($dropPath) . ' 2>' . escapeshellarg($dropErrPath);
    $dropCode = 0;
    exec($dropCmd, $dummy, $dropCode);
    $raw = @file_get_contents($dropErrPath);
    $dropErr = ($raw === false) ? '' : trim($raw);
    @unlink($dropErrPath);
    @unlink($dropPath);

    // Verified by re-listing rather than trusted from the exit code: a view
    // whose definer no longer exists, or a table this user has no DROP grant
    // on, fails for that statement alone.
    $after = wruListTables($dbUser, $dbPass, $dbName, $attempts, $uploadDir . '/.wru-tables');
    $remaining = is_array($after) ? (count($after['tables']) + count($after['views'])) : -1;
    $remainingNames = is_array($after) ? array_merge($after['tables'], $after['views']) : array();
    $dropOk = ($dropCode === 0 && $remaining === 0);
    echo json_encode(array(
        'ok' => $dropOk,
        'database' => $dbName,
        'via' => $listed['label'],
        'client' => wruMysqlBin(),
        'dropped_tables' => count($tables),
        'dropped_views' => count($views),
        'remaining' => $remaining,
        'remaining_names' => array_slice($remainingNames, 0, 25),
        'backup' => $backup,
        'disk_free' => @disk_free_space($uploadDir),
        'error' => $dropOk
            ? null
            : ('mysql exit ' . $dropCode . ($dropErr !== '' ? ': ' . $dropErr : '') .
                '; ' . $remaining . ' object(s) still present' .
                (is_array($after) ? '' : ' (could not re-list: ' . $after . ')')),
    ));
    exit;
}

/**
 * Empties this docroot server-side, preserving this script and the staging dir.
 *
 * The alternative is deleting the tree over FTP, one command per file. For a
 * Bitrix install that is tens of thousands of round trips: measured live on
 * madamsportik.ru, an FTP wipe was still running after ten minutes with the site
 * already returning 403, whereas this is a single `find ... -exec rm -rf`. On a
 * reroll onto a live site that difference IS the outage, which is the whole
 * reason the wipe was moved to just before the restore in the first place.
 *
 * Deletes only top-level entries (rm -rf recurses from there), so the exclusions
 * are simple names rather than paths.
 */
/**
 * Lists the staging directory. Read-only, no side effects.
 *
 * Exists because "is the transferred archive still there?" otherwise has no
 * answer short of attempting the restore and reading its failure — and the
 * staging dir holds the only local copies of both the incoming backup and the
 * pre-wipe rollback, so guessing about its contents is guessing about whether a
 * rollback is still possible.
 */
/**
 * Streams one file out of the staging directory.
 *
 * The staging dir is a dot-directory inside the docroot, and a CMS .htaccess
 * routes/denies it — confirmed live: fetching the path directly returned Bitrix's
 * own 404 page. So the only way to retrieve a pre-drop database dump (the sole
 * copy of the destination's original data, which the next restore overwrites) is
 * through this script.
 *
 * basename() on the requested name and a whitelist pattern: this must not become
 * a way to read arbitrary files off the server.
 */
if ($action === 'staging_get') {
    $name = isset($_REQUEST['name']) ? basename($_REQUEST['name']) : '';
    if (!preg_match('/^wru-(backup|predrop|prewipe)-[0-9]{14}\.(sql|tar\.gz)$/', $name)) {
        echo json_encode(array('ok' => false, 'error' => 'invalid or non-whitelisted filename: ' . $name));
        exit;
    }
    $path = $uploadDir . '/' . $name;
    if (!is_file($path)) {
        echo json_encode(array('ok' => false, 'error' => 'not found in staging dir: ' . $name));
        exit;
    }
    // Replaces the JSON content type set at the top of this script — this
    // response is the file itself, not a status report.
    header('Content-Type: application/octet-stream');
    header('Content-Length: ' . filesize($path));
    header('Content-Disposition: attachment; filename="' . $name . '"');
    // Output buffering would try to hold the whole file in memory first, which
    // fails on a large archive against a modest memory_limit.
    while (ob_get_level() > 0) {
        ob_end_clean();
    }
    readfile($path);
    exit;
}

/**
 * Recreates symlinks in this docroot from a caller-supplied list.
 *
 * The destination half of mini-backup.php's ?action=symlinks inventory, for a
 * Bitrix multisite whose sister sites reach a shared Bitrix kernel through
 * links. tar carries such a link's target STRING but not the target itself, and
 * the old string names a path that does not exist on this server — ISPConfig
 * assigns different client/web numbers here. So the caller sends the links with
 * targets already rewritten to this server's paths, and this creates them.
 *
 * Refuses to replace anything that is not already a symlink: after a restore the
 * docroot holds real site data, and silently swapping a real directory for a
 * link would destroy it. Reports per-link so a partial result is visible rather
 * than averaged into one boolean.
 */
/**
 * Read-only inventory of this docroot's symlinks — the destination-side twin of
 * mini-backup.php's ?action=symlinks, kept here so the destination can be
 * inspected BEFORE and AFTER a reroll without deploying the backup script to it.
 *
 * On a multisite sister this is the difference between "the site is broken" and
 * "the site's bitrix link points at a path that no longer exists".
 */
if ($action === 'symlinks') {
    $links = array();
    wruCollectSymlinks($realDocRoot, $realDocRoot, $links, 0);
    $outside = 0;
    $dangling = 0;
    foreach ($links as $l) {
        if (!$l['inside_docroot']) {
            $outside++;
        }
        if ($l['dangling']) {
            $dangling++;
        }
    }
    echo json_encode(array(
        'ok' => true,
        'docroot' => $realDocRoot,
        'count' => count($links),
        'needing_rewrite' => $outside,
        'dangling' => $dangling,
        'links' => $links,
    ));
    exit;
}

if ($action === 'make_symlinks') {
    $raw = isset($_POST['links']) ? $_POST['links'] : '';
    $decoded = json_decode($raw, true);
    if (!is_array($decoded)) {
        echo json_encode(array('ok' => false, 'error' => 'links must be a JSON array of {path,target}'));
        exit;
    }
    $results = array();
    $allOk = true;
    foreach ($decoded as $link) {
        $path = isset($link['path']) ? $link['path'] : '';
        $target = isset($link['target']) ? $link['target'] : '';
        $entry = array('path' => $path, 'target' => $target, 'ok' => false, 'note' => null);

        // Path is ours to place inside the docroot; a traversal or an absolute
        // path would let the caller write links anywhere on the server.
        if ($path === '' || $target === '' || strpos($path, '..') !== false || substr($path, 0, 1) === '/') {
            $entry['note'] = 'invalid path or empty target';
            $results[] = $entry;
            $allOk = false;
            continue;
        }
        $full = $realDocRoot . '/' . ltrim($path, '/');

        if (is_link($full)) {
            $was = @readlink($full);
            if ($was === $target) {
                $entry['ok'] = true;
                $entry['note'] = 'already points there — left alone';
                $results[] = $entry;
                continue;
            }
            if (!@unlink($full)) {
                $entry['note'] = 'existing symlink could not be removed (was: ' . $was . ')';
                $results[] = $entry;
                $allOk = false;
                continue;
            }
            $entry['note'] = 'replaced a symlink that pointed at ' . $was;
        } elseif (file_exists($full)) {
            // Real file or directory: never clobbered. On a sister site this is
            // usually the restore having extracted a REAL copy of the shared
            // directory instead of the link, which the operator needs to know
            // about rather than have quietly deleted.
            $entry['note'] = 'refusing to replace: a real ' . (is_dir($full) ? 'directory' : 'file') .
                ' already exists at this path';
            $results[] = $entry;
            $allOk = false;
            continue;
        }

        $parent = dirname($full);
        if (!is_dir($parent) && !@mkdir($parent, 0755, true)) {
            $entry['note'] = 'could not create parent directory ' . $parent;
            $results[] = $entry;
            $allOk = false;
            continue;
        }
        if (!@symlink($target, $full)) {
            $entry['note'] = ($entry['note'] === null ? '' : $entry['note'] . '; ') . 'symlink() failed';
            $results[] = $entry;
            $allOk = false;
            continue;
        }
        // Verified rather than assumed: a link can be created and still not
        // resolve, which is the failure that matters for a shared kernel.
        $entry['ok'] = true;
        $entry['resolves'] = file_exists($full);
        if (!$entry['resolves']) {
            $entry['note'] = ($entry['note'] === null ? '' : $entry['note'] . '; ') .
                'CREATED BUT DANGLING — the target does not exist on this server';
            $allOk = false;
        }
        $results[] = $entry;
    }
    echo json_encode(array('ok' => $allOk, 'docroot' => $realDocRoot, 'links' => $results));
    exit;
}

if ($action === 'staging_list') {
    $entries = @scandir($uploadDir);
    if ($entries === false) {
        echo json_encode(array('ok' => false, 'error' => 'staging dir not readable: ' . $uploadDir));
        exit;
    }
    $files = array();
    foreach ($entries as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        $p = $uploadDir . '/' . $entry;
        $files[] = array(
            'name' => $entry,
            'size' => is_file($p) ? filesize($p) : null,
            'is_dir' => is_dir($p),
            'mtime' => @filemtime($p),
        );
    }
    echo json_encode(array(
        'ok' => true,
        'dir' => $uploadDir,
        'docroot' => $realDocRoot,
        'files' => $files,
        'disk_free' => @disk_free_space($uploadDir),
    ));
    exit;
}

if ($action === 'wipe_docroot') {
    // What must survive: this script (so the caller can still reach the restore
    // action afterwards) and the staging dir holding the already-transferred
    // archive. Losing the latter means transferring hundreds of megabytes again.
    // A TOTAL wipe has to be asked for explicitly. The pipeline now empties the
    // destination BEFORE deploying the toolkit (cleanup at step 7, toolkit at
    // step 8), so at that point there is nothing worth preserving and the
    // operator's expectation is simply "everything is gone". Requested with
    // keep_self=0; absent that, the preserve list below applies as before.
    //
    // It is a parameter rather than the default because the SAME action is used
    // mid-migration, where preserving the staging dir is what avoids
    // re-transferring hundreds of megabytes.
    // Echoed back in the response. A build that predates this parameter simply
    // omits the field, which is how the caller detects version skew: PHP ignores
    // unknown POST parameters silently, so "keep_self=0 was accepted" and
    // "keep_self=0 was never understood" are otherwise indistinguishable. That
    // ambiguity is exactly what let a total wipe report success while preserving
    // this script and a 1.6 GB staging directory.
    $keepSelf = !(isset($_REQUEST['keep_self']) && $_REQUEST['keep_self'] === '0');

    $keep = array();
    $selfName = basename(__FILE__);
    if (!$keepSelf) {
        // Deliberately empty: this script deletes itself along with everything
        // else. Safe mid-request - the file is already open and compiled, so
        // execution continues to completion; only the next request would 404.
        // The caller must redeploy before using any other action.
        $keep = array();
    } elseif ($scriptDir === $realDocRoot) {
        $keep[] = $selfName;
        $keep[] = $uploadDirName;
    } elseif (strpos($scriptDir, $realDocRoot . '/') === 0) {
        // Script lives in a subdirectory (deployMiniScript's fallback for a site
        // whose .htaccess swallows PHP at the root). The staging dir is inside
        // that same subdirectory, so preserving the subdirectory covers both —
        // at the cost of preserving whatever else is in it, which the caller is
        // told about rather than left to discover.
        $rel = substr($scriptDir, strlen($realDocRoot) + 1);
        $parts = explode('/', $rel);
        $keep[] = $parts[0];
    }

    // FAIL CLOSED. An empty preserve list means this code could not work out
    // where its own script and staging directory are — and in that state the
    // difference between "preserve nothing" and "delete everything" is invisible.
    // That is exactly how a 718 MB archive and the pre-wipe rollback snapshot
    // were destroyed here once already, because a symlinked docroot made the
    // path comparison above fail silently. Refusing costs a retry; guessing
    // costs the rollback.
    // Fires only when the preserve list was SUPPOSED to be populated. A total
    // wipe asked for with keep_self=0 legitimately has an empty list, and must
    // not be blocked by a guard whose purpose is catching the case where the
    // script could not locate itself.
    if ($keepSelf && count($keep) === 0) {
        echo json_encode(array(
            'ok' => false,
            'error' => 'refusing to wipe: could not locate this script relative to the docroot, so nothing ' .
                'could be marked for preservation — wiping now would delete the staging directory holding ' .
                'the transferred backup. script dir "' . $scriptDir . '", docroot "' . $realDocRoot . '".',
        ));
        exit;
    }

    $before = @scandir($realDocRoot);
    if ($before === false) {
        echo json_encode(array('ok' => false, 'error' => 'could not read the docroot: ' . $realDocRoot));
        exit;
    }

    $deleted = 0;
    $failures = array();
    $diag = array();
    foreach ($before as $entry) {
        if ($entry === '.' || $entry === '..' || in_array($entry, $keep)) {
            continue;
        }
        $r = wruRmTree($realDocRoot . '/' . $entry, $diag);
        $deleted += $r[0];
        $failures = array_merge($failures, $r[1]);
    }
    $err = count($failures) ? (count($failures) . ' path(s) could not be removed, e.g. ' . implode(', ', array_slice($failures, 0, 5))) : '';

    // Verified by re-listing rather than trusted from the delete loop: a file the
    // PHP user cannot unlink fails individually, and a docroot that still has the
    // old site in it would otherwise be reported as wiped.
    $after = @scandir($realDocRoot);
    if ($after === false) {
        $after = array();
    }
    $leftover = array();
    foreach ($after as $entry) {
        if ($entry === '.' || $entry === '..') {
            continue;
        }
        if (!in_array($entry, $keep)) {
            $leftover[] = $entry;
        }
    }
    $removed = array();
    foreach ($before as $entry) {
        if ($entry === '.' || $entry === '..' || in_array($entry, $keep)) {
            continue;
        }
        if (!in_array($entry, $leftover)) {
            $removed[] = $entry;
        }
    }
    // Classify WHY, when it fails. "147 paths could not be removed" invites a
    // retry; "these paths belong to uid 5061 and we are uid 5017" names a cause
    // no retry can fix — the parent directories are another site user's, mode
    // 0755, so this user can neither unlink inside them nor chmod them, and the
    // FTP account hits the same wall because it is the same user. It also means
    // the subsequent tar extraction cannot overwrite those paths, so the restore
    // would silently keep the OLD site's copies of them. That needs a chown by
    // root on the server, which is outside anything wr-util can reach.
    $foreignUids = array();
    $processUid = function_exists('posix_geteuid') ? posix_geteuid() : null;
    foreach ($diag as $d) {
        foreach (array('owner_uid', 'parent_owner_uid') as $k) {
            if (isset($d[$k]) && $d[$k] !== false && $d[$k] !== null && $processUid !== null && $d[$k] != $processUid) {
                if (!in_array($d[$k], $foreignUids)) {
                    $foreignUids[] = $d[$k];
                }
            }
        }
    }

    $wipeOk = (count($leftover) === 0);
    echo json_encode(array(
        'ok' => $wipeOk,
        'docroot' => $realDocRoot,
        'preserved' => $keep,
        'keep_self_honoured' => $keepSelf ? 1 : 0,
        'removed' => $removed,
        'removed_count' => count($removed),
        'files_deleted' => $deleted,
        'leftover' => array_slice($leftover, 0, 25),
        'failed_paths' => array_slice($failures, 0, 10),
        'diagnostics' => $diag,
        'process_uid' => $processUid,
        'foreign_owner_uids' => $foreignUids,
        'error' => $wipeOk ? null : ('could not remove ' . count($leftover) . ' top-level entr(ies)' . ($err !== '' ? '; ' . $err : '')),
    ));
    exit;
}

/**
 * Archives this docroot into the staging dir — the rollback for the webroot
 * wipe wr-util performs over FTP straight afterwards. Only meaningful when
 * restoring onto a site that already has content worth keeping a copy of.
 *
 * Excludes the staging dir itself: it already holds the incoming backup, so
 * including it would roughly double the space needed and have tar archiving
 * files that are being written as it reads them.
 */
if ($action === 'fs_snapshot') {
    if (!function_exists('exec')) {
        echo json_encode(array('ok' => false, 'error' => 'exec() is disabled on this host — cannot shell out to tar'));
        exit;
    }

    // Idempotent: an existing snapshot is REUSED rather than joined by a second
    // one. This matters for rollback integrity, not just for saving time. The
    // wipe step can legitimately be re-run after a partial failure, and by then
    // the docroot is half-deleted — so a fresh snapshot would capture the broken
    // intermediate state and, being the newest, would look like the authoritative
    // copy to roll back to. The first snapshot is the one taken while the site was
    // still whole, and it is the one worth keeping. Confirmed needed live: an FTP
    // wipe died with ECONNRESET partway through, after its snapshot had succeeded.
    $existing = @glob($uploadDir . '/wru-prewipe-*.tar.gz');
    if (is_array($existing) && count($existing)) {
        sort($existing);
        $keepPath = $existing[0];
        if (is_file($keepPath) && filesize($keepPath) > 0) {
            echo json_encode(array(
                'ok' => true,
                'name' => basename($keepPath),
                'size' => filesize($keepPath),
                'docroot' => $realDocRoot,
                'disk_free' => @disk_free_space($uploadDir),
                'reused' => true,
                'warnings' => null,
                'error' => null,
            ));
            exit;
        }
    }

    $name = 'wru-prewipe-' . gmdate('YmdHis') . '.tar.gz';
    $dest = $uploadDir . '/' . $name;
    // Computed relative to tar's -C target rather than assumed to be
    // "./.wru-restore": the staging dir sits next to the SCRIPT, and the
    // script is not necessarily at the docroot root (deployMiniScript falls
    // back to a subdirectory when the site's own .htaccess swallows PHP
    // there).
    $excludeArgs = '';
    if (strpos($uploadDir, $realDocRoot . '/') === 0) {
        $excludeArgs = ' --exclude=' . escapeshellarg('./' . substr($uploadDir, strlen($realDocRoot) + 1));
    }
    $snapErrPath = $dest . '.err';
    $cmd = 'tar' . $excludeArgs . ' -czf ' . escapeshellarg($dest) .
        ' -C ' . escapeshellarg($realDocRoot) . ' . 2>' . escapeshellarg($snapErrPath);
    $code = 0;
    exec($cmd, $dummy, $code);
    $raw = @file_get_contents($snapErrPath);
    $err = ($raw === false) ? '' : trim($raw);
    @unlink($snapErrPath);
    $size = is_file($dest) ? filesize($dest) : 0;
    // tar signals warnings and hard errors through the same exit status
    // family: 1 is "something was odd" (classically "file changed as we read
    // it", which is expected on a site still serving traffic) and 2 is a real
    // failure. A warning-only run still produces a usable archive, so it is
    // accepted with the warnings passed back rather than discarded.
    $ok = ($code === 0 || $code === 1) && $size > 0;
    echo json_encode(array(
        'ok' => $ok,
        'name' => $ok ? $name : null,
        'size' => $size,
        'docroot' => $realDocRoot,
        'disk_free' => @disk_free_space($uploadDir),
        'warnings' => ($ok && $err !== '') ? $err : null,
        'error' => $ok ? null : ('tar exit ' . $code . ', ' . $size . ' bytes' . ($err !== '' ? ': ' . $err : '')),
    ));
    exit;
}

// Literal search/replace on one config file (e.g. rewriting the copied-
// over app config's OLD DB credentials to the NEW destination ones) — no
// framework-specific parsing here, the caller supplies the exact old/new
// strings to match (see migrate.ts's restoreDestination, which knows the
// per-framework config path and what the old/new values actually are).
// $count from str_replace's 4th (by-reference) param — supported since
// PHP 5.0 — reports how many occurrences each pattern actually matched,
// so a 0-match replacement (wrong assumption about the config format) is
// visible rather than silently swallowed.
if ($action === 'fix_config') {
    $configPath = isset($_POST['config_path']) ? $_POST['config_path'] : '';
    if ($configPath === '' || strpos($configPath, '..') !== false) {
        echo json_encode(array('ok' => false, 'error' => 'invalid config_path'));
        exit;
    }
    $fullPath = $realDocRoot . '/' . ltrim($configPath, '/');
    if (!is_file($fullPath)) {
        echo json_encode(array('ok' => false, 'error' => 'config file not found: ' . $configPath));
        exit;
    }
    $content = file_get_contents($fullPath);
    if ($content === false) {
        echo json_encode(array('ok' => false, 'error' => 'could not read config file'));
        exit;
    }
    $replacementsRaw = isset($_POST['replacements']) ? $_POST['replacements'] : '[]';
    $replacements = json_decode($replacementsRaw, true);
    if (!is_array($replacements)) {
        $replacements = array();
    }
    $report = array();
    foreach ($replacements as $pair) {
        if (!isset($pair['from']) || !isset($pair['to'])) {
            continue;
        }
        $n = 0;
        $content = str_replace($pair['from'], $pair['to'], $content, $n);
        $report[] = $pair['from'] . ' => ' . $n . ' replacement(s)';
    }
    if (@file_put_contents($fullPath, $content) === false) {
        echo json_encode(array('ok' => false, 'error' => 'could not write config file'));
        exit;
    }
    echo json_encode(array('ok' => true, 'report' => $report));
    exit;
}

/**
 * Locates the directory holding a Bitrix install ("bitrix/" plus at least
 * one of its two config files). The archive extracts AT the docroot, so
 * that's the normal answer — but a source whose site actually lived one
 * level down (its own docroot pointing into a subdirectory) archives that
 * structure verbatim, so check one level of subdirectories too. Mirrors
 * restore-42.php's findFrameworkRoot in spirit; kept deliberately shallow
 * (no recursion) since a real Bitrix root is never buried deeper than that.
 */
function wruFindBitrixRoot($docRoot)
{
    $candidates = array($docRoot);
    $entries = @scandir($docRoot);
    if (is_array($entries)) {
        foreach ($entries as $e) {
            if ($e === '.' || $e === '..') {
                continue;
            }
            if (is_dir($docRoot . '/' . $e)) {
                $candidates[] = $docRoot . '/' . $e;
            }
        }
    }
    foreach ($candidates as $dir) {
        if (is_file($dir . '/bitrix/.settings.php') || is_file($dir . '/bitrix/php_interface/dbconn.php')) {
            return $dir;
        }
    }
    return null;
}

/** Escapes a value for embedding in a single- or double-quoted PHP string
 * literal — backslash first, then the quote character itself. Equivalent to
 * restore-42.php's phpStrEscape. */
function wruPhpStrEscape($v, $quote)
{
    return str_replace($quote, '\\' . $quote, str_replace('\\', '\\\\', $v));
}

// Rewrites a restored Bitrix install's DB credentials to this destination's
// (baked in at deploy time, see the $WRU_DB_* block above).
//
// Bitrix can hold those credentials in bitrix/.settings.php (D7, nested
// array syntax) and/or bitrix/php_interface/dbconn.php (legacy, $DB*
// variables). Confirmed live on a real migrated site (ic-info.ru) that BOTH
// files can be present and both can carry a full set of credentials — so
// each file is handled independently rather than stopping at whichever is
// found first, since fixing only one leaves the other still pointing at the
// source server's database. Either file may also be absent, or present but
// carrying no credentials at all; neither case is an error, it just means
// there is nothing to rewrite there.
//
// Regex-based rather than the literal search/replace fix_config action
// above, because the caller can't know which quoting style or spacing a
// given install happens to use. Each pattern's match count is reported, so
// a file whose format doesn't match these assumptions shows up as an
// explicit 0 rather than being silently skipped.
if ($action === 'fix_bitrix') {
    // The action name is historical. What it does is repoint whatever config the
    // restored site actually uses at the destination's own database, and Bitrix
    // is only one of the shapes that config comes in.
    //
    // Refusing outright when no Bitrix install is found was wrong: on a Webasyst
    // shop it meant the step failed, the site kept the SOURCE's credentials, and
    // the only symptom was a database error on the restored site. There is no
    // Bitrix root to find there, and no need for one.
    $root = wruFindBitrixRoot($realDocRoot);
    if ($root === null) {
        $root = $realDocRoot;
    }

    $dbHostVal = $WRU_DB_HOST !== '' ? $WRU_DB_HOST : 'localhost';
    $report = array();
    $filesChanged = 0;
    $credsFound = 0;

    // Each entry: file path, and the patterns to rewrite in it. 'q' is the
    // quote style to emit; both quote styles are always *matched* (a real
    // install can use either) regardless of which one it happens to use.
    $targets = array(
        array(
            'label' => '.settings.php',
            'path' => $root . '/bitrix/.settings.php',
            // Array-key form: 'host' => 'value'. The keys are specific
            // enough not to collide elsewhere in the file — verified on the
            // real site above, where each appears exactly once — and the
            // reported counts make any collision visible if one ever does.
            'kind' => 'array_key',
            'map' => array(
                'host' => $dbHostVal,
                'login' => $WRU_DB_USER,
                'password' => $WRU_DB_PASS,
                'database' => $WRU_DB_NAME,
            ),
        ),
        array(
            // Webasyst / Shop-Script. Same 'key' => 'value' shape as Bitrix's
            // D7 .settings.php, so the existing array_key rewriter handles it
            // unchanged. Keys are Webasyst's own names, which differ from
            // Bitrix's ('user' not 'login').
            'label' => 'wa-config/db.php',
            'path' => $realDocRoot . '/wa-config/db.php',
            'kind' => 'array_key',
            'map' => array(
                'host' => $dbHostVal,
                'user' => $WRU_DB_USER,
                'password' => $WRU_DB_PASS,
                'database' => $WRU_DB_NAME,
            ),
        ),
        array(
            'label' => 'dbconn.php',
            'path' => $root . '/bitrix/php_interface/dbconn.php',
            // Variable-assignment form: $DBHost = "value";
            'kind' => 'php_var',
            'map' => array(
                'DBHost' => $dbHostVal,
                'DBLogin' => $WRU_DB_USER,
                'DBPassword' => $WRU_DB_PASS,
                'DBName' => $WRU_DB_NAME,
            ),
        ),
    );

    foreach ($targets as $t) {
        if (!is_file($t['path'])) {
            $report[] = $t['label'] . ': not present — nothing to do';
            continue;
        }
        $s = file_get_contents($t['path']);
        if ($s === false) {
            echo json_encode(array('ok' => false, 'error' => 'could not read ' . $t['label']));
            exit;
        }

        $orig = $s;
        $total = 0;
        $detail = array();
        foreach ($t['map'] as $name => $val) {
            $hits = 0;
            if ($t['kind'] === 'array_key') {
                foreach (array("'", '"') as $q) {
                    $n = 0;
                    $s = preg_replace(
                        '/' . $q . preg_quote($name, '/') . $q . '\\s*=>\\s*' . $q . '[^' . $q . ']*' . $q . '/',
                        "'" . $name . "' => '" . wruPhpStrEscape($val, "'") . "'",
                        $s,
                        -1,
                        $n
                    );
                    $hits += $n;
                }
            } else {
                foreach (array("'", '"') as $q) {
                    $n = 0;
                    // Always EMIT a single-quoted literal, whichever style
                    // the file used. In a double-quoted PHP string a "$" is
                    // interpolation, so a password like 'pa$$w0rd' written
                    // into "..." silently evaluates to 'pa' plus an
                    // undefined variable — the site then can't connect, with
                    // nothing in the file looking obviously wrong. Single
                    // quotes interpolate nothing, so only \ and ' need
                    // escaping (see wruPhpStrEscape).
                    $s = preg_replace(
                        '/\\$' . preg_quote($name, '/') . '\\s*=\\s*' . $q . '[^' . $q . ']*' . $q . '/',
                        '$' . $name . " = '" . wruPhpStrEscape($val, "'") . "'",
                        $s,
                        -1,
                        $n
                    );
                    $hits += $n;
                }
            }
            $detail[] = $name . '=' . $hits;
            $total += $hits;
        }

        if ($total === 0) {
            // Present but holding no DB credentials — a real possibility
            // (e.g. a dbconn.php that only sets cache/permission constants).
            // Deliberately NOT written back: no need to touch a file we
            // aren't actually changing.
            $report[] = $t['label'] . ': present but no DB credentials found — left untouched';
            continue;
        }
        if ($s === $orig) {
            // Matched, but every value was already correct.
            $report[] = $t['label'] . ': already pointing at the new credentials (' . implode(' ', $detail) . ')';
            $credsFound++;
            continue;
        }
        if (@file_put_contents($t['path'], $s) === false) {
            echo json_encode(array('ok' => false, 'error' => 'could not write ' . $t['label']));
            exit;
        }
        $report[] = $t['label'] . ': updated (' . implode(' ', $detail) . ')';
        $filesChanged++;
        $credsFound++;
    }

    // No credentials anywhere is worth flagging: the site was detected as
    // Bitrix, so something should have carried DB credentials. Reported as a
    // warning rather than a hard failure — the extraction and import already
    // succeeded by this point, and the caller surfaces it for a manual look.
    echo json_encode(array(
        'ok' => true,
        'root' => $root,
        'files_changed' => $filesChanged,
        'creds_found' => $credsFound,
        'warning' => $credsFound === 0 ? 'no DB credentials found in either Bitrix config file — check them by hand' : '',
        'report' => $report,
    ));
    exit;
}

// Points a restored Bitrix install at its new domain by setting the Main
// module's "server_name" option. Confirmed in restore-42.php's own notes
// (verified there via a live Set-Cookie header): Bitrix builds the session
// cookie's Domain attribute from this value, and browsers reject the cookie
// outright when it doesn't match the site being visited — so nobody can
// stay logged in until it's correct. It's also what builds absolute URLs
// outside a request context (cron agents, notifications, RSS, sitemaps).
//
// The target domain is passed in explicitly rather than taken from this
// request's own Host header (restore-42.php's approach): wr-util reaches
// the destination via its auto-generated service domain pre-cutover, so the
// request host here is exactly the wrong value to bake in.
if ($action === 'bitrix_set_domain') {
    if (!function_exists('exec')) {
        echo json_encode(array('ok' => false, 'error' => 'exec() is disabled on this host — cannot shell out to mysql'));
        exit;
    }
    $domain = isset($_POST['domain']) ? $_POST['domain'] : '';
    // Validated rather than escaped: this value goes into a SQL literal, and
    // a strict hostname pattern leaves nothing that needs escaping at all.
    if (!preg_match('/^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)+$/i', $domain)) {
        echo json_encode(array('ok' => false, 'error' => 'invalid domain'));
        exit;
    }
    if ($WRU_DB_NAME === '') {
        echo json_encode(array('ok' => false, 'error' => 'no database configured for this deployment'));
        exit;
    }

    // UPDATE-then-conditional-INSERT rather than INSERT ... ON DUPLICATE KEY
    // UPDATE: b_option's unique key includes SITE_ID in most Bitrix
    // versions, so an upsert would need assumptions about that column this
    // doesn't have to make. The UPDATE deliberately has no SITE_ID clause —
    // every per-site row for main.server_name should point at the new
    // domain.
    $sql = "UPDATE b_option SET VALUE = '" . $domain . "' WHERE MODULE_ID = 'main' AND NAME = 'server_name';\n"
        . "INSERT INTO b_option (MODULE_ID, NAME, VALUE) SELECT 'main', 'server_name', '" . $domain . "'"
        . " FROM DUAL WHERE NOT EXISTS (SELECT 1 FROM b_option WHERE MODULE_ID = 'main' AND NAME = 'server_name');\n";
    $sqlFile = $uploadDir . '/.wru-bitrix-domain.sql';
    if (@file_put_contents($sqlFile, $sql) === false) {
        echo json_encode(array('ok' => false, 'error' => 'could not write temp sql file'));
        exit;
    }

    $dbHost = $WRU_DB_HOST !== '' ? $WRU_DB_HOST : 'localhost';
    $dbPort = $WRU_DB_PORT !== '' ? $WRU_DB_PORT : '3306';
    $errFile = $sqlFile . '.err';
    // Socket-then-TCP, same reason as the restore import — see
    // wruMysqlConnAttempts. MYSQL_PWD rather than -p so the password does not
    // appear in `ps`.
    $code = 1;
    $err = '';
    foreach (wruMysqlConnAttempts($dbHost, $dbPort) as $connArgs) {
        $cmd = 'MYSQL_PWD=' . escapeshellarg($WRU_DB_PASS) . ' ' . wruMysqlBin() . ' ' . $connArgs .
            ' -u ' . escapeshellarg($WRU_DB_USER) .
            ' ' . escapeshellarg($WRU_DB_NAME) .
            ' < ' . escapeshellarg($sqlFile) . ' 2>' . escapeshellarg($errFile);
        $code = 0;
        exec($cmd, $dummy, $code);
        $raw = @file_get_contents($errFile);
        $err = ($raw === false) ? '' : trim($raw);
        @unlink($errFile);
        if ($code === 0) {
            break;
        }
        if (!wruIsTransportError($err)) {
            break;
        }
    }
    @unlink($sqlFile);
    if ($code !== 0) {
        echo json_encode(array('ok' => false, 'error' => 'mysql failed: ' . $err));
        exit;
    }
    echo json_encode(array('ok' => true, 'domain' => $domain, 'warnings' => trim($err === false ? '' : $err)));
    exit;
}

echo json_encode(array('ok' => false, 'error' => 'unknown action'));
