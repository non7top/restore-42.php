<?php
/**
 * wr-util mini backup helper.
 *
 * Deployed with a randomly generated filename and a per-deployment token
 * baked in at deploy time (both replaced by ftpClient's miniScriptClient
 * before upload — see wr-util's src/main/miniScriptClient.ts) — this file
 * as checked into the repo is only ever a template.
 *
 * Exists because the full restore-42.php uses PHP 7+ syntax (return type
 * declarations etc.) that some legacy hosts' PHP simply cannot parse —
 * confirmed live via a PHP 5.3.3 host's own error log. This file is
 * intentionally written against PHP 5.2/5.3 syntax only: no return type
 * hints, no short array syntax, no null coalescing, no scalar type hints.
 *
 * Does exactly one thing: tar+gzip the docroot (excluding itself and its
 * own backup directory) and, if DB credentials are given, mysqldump the
 * database — nothing else. No framework detection, no config rewriting.
 * Anything site-specific worth skipping is passed in by the caller as
 * `excludes` (see ?action=start), keeping that knowledge in wr-util.
 *
 * The work runs DETACHED and is polled via ?action=status, rather than
 * happening inline in one long request.
 *
 * Observed live on ic-info.ru (these parts are measured, not inferred): a
 * 4.0 GB docroot took tar ~5m11s; the .sql file was created at the moment tar
 * finished and was still 0 bytes 30 minutes later; the caller's request ended
 * in a dropped connection ("fetch failed"). So the request died at roughly
 * five minutes of work, taking mysqldump with it and leaving a complete
 * archive beside an empty dump.
 *
 * Which timeout fired was NOT determined — a web-server/FCGI read timeout is
 * the likeliest candidate (PHP's own max_execution_time is documented not to
 * count time inside exec() on Linux), but that was never confirmed against
 * this host's config. Detaching makes the question moot rather than answering
 * it: once the work no longer lives inside the request, no request-lifetime
 * limit can truncate it.
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
 * This file is the one that matters most: it carries the site's DB credentials
 * baked in, so an unexpired orphan can dump the database over HTTP.
 *
 * FAILS CLOSED: missing, non-numeric, or still the raw placeholder (i.e. this
 * file was copied rather than deployed) refuses everything.
 *
 * Duplicated VERBATIM in mini-backup.php, mini-download.php and
 * mini-restore.php — they are deployed independently and cannot share an
 * include. Keep the three copies identical.
 */
$WRU_DEADLINE = '__WRU_DEADLINE__';

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
 * It used to be read from $_GET, so a live credential was written into the
 * site's plaintext HTTP access log on every single call and then rotated into
 * whatever archives that log feeds. Same reasoning as the DB credentials
 * above, which were already baked in for exactly this reason.
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

// Every response here is either JSON or a binary stream, so ANY PHP notice or
// warning printed inline corrupts it — the caller's JSON.parse then fails with
// something like "Unexpected token '<'" that says nothing about the real
// cause. Seen for real: on a host with no date.timezone set, date()'s warning
// was emitted ahead of the JSON body. Errors are still reported, just through
// the JSON itself rather than by printing into it.
@ini_set('display_errors', '0');
@ini_set('html_errors', '0');

// filesize() is 32-bit on some legacy hosts and cannot report a file larger than
// 2 GB — it returns 0 (or a wrapped value) with no error. Measured on
// legacy1.wr0.ru (32-bit CentOS 5, PHP 5.1.6): a completed 7,913,280,346-byte
// archive reported size 0 while tar.code was 0, so the caller decided
// "mini-backup produced no archive" and discarded a perfectly good 7.9 GB
// backup. An earlier attempt reported 2,003,628,032 for the same growing file,
// which also made the progress log look like tar had stalled at ~2 GB.
//
// `stat -c %s` is 64-bit clean and present on every host this runs on, so it is
// tried first and filesize() is only the fallback.
function wru_filesize($path)
{
    // Deliberately NOT gated on is_file(): that call goes through the same
    // 32-bit stat and ALSO fails on a file larger than 2 GB, which silently
    // defeated the whole point of this helper the first time it was written.
    // Measured on legacy1: for a 7.9 GB archive, both filesize() and is_file()
    // fail while `stat -c %s` returns the correct value.
    $out = @shell_exec('stat -c %s ' . escapeshellarg($path) . ' 2>/dev/null');
    if ($out !== null) {
        $out = trim($out);
        if ($out !== '' && preg_match('/^[0-9]+$/', $out)) {
            // Returned as a string: a value above PHP_INT_MAX on a 32-bit build
            // would be mangled by an int cast, and it is only ever echoed as
            // JSON or compared for ">0".
            return $out;
        }
    }
    $fs = @filesize($path);
    if ($fs !== false) {
        return $fs;
    }
    // Last resort: the file may exist but be unmeasurable by 32-bit stat. Report
    // 0 only if it genuinely cannot be opened, so callers do not treat an
    // unmeasurable-but-present archive as a missing one.
    $fh = @fopen($path, 'rb');
    if ($fh !== false) {
        fclose($fh);
        return 'unknown';
    }
    return 0;
}


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

// Reachability check only — no backup performed. Lets the deploying side
// confirm this exact file actually executes (rather than being swallowed
// by the site's own .htaccess) before triggering the real, heavier action.
//
// Carries NO token: it is exactly the call that used to write a live
// credential into the access log, and it needs no authority to do its job.
// PHP_VERSION was dropped for the same reason — an unauthenticated caller has
// no business being told it, and probePhpVersion answers that separately.
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

// __DIR__ is wherever THIS script landed, which is not necessarily the
// site's actual docroot — some hosts' .htaccess swallows PHP requests at
// the real docroot root, forcing deployment into a subdirectory (see
// deployMiniScript's root->public->files fallback). The docroot to back up
// is always $_SERVER['DOCUMENT_ROOT'] (confirmed live: backing up __DIR__
// instead silently archived only the 3-file subdirectory the script
// happened to be sitting in, not the site).
// Both resolved through realpath() before being compared or subtracted from one
// another. ISPConfig serves each site from /var/www/<domain>/web, a SYMLINK to
// /var/www/clients/client<N>/web<M>/web, so DOCUMENT_ROOT and __DIR__ regularly
// name the same directory by different strings. The str_replace() below then
// matches nothing, $relScriptDir comes out as a full absolute path, and the
// --exclude built from it silently stops excluding this script from its own
// archive. (The same raw-string comparison, in mini-restore.php's wipe, deleted
// a staging directory holding a 718 MB transferred archive.)
$rawDocRoot = (isset($_SERVER['DOCUMENT_ROOT']) && $_SERVER['DOCUMENT_ROOT'] !== '') ? $_SERVER['DOCUMENT_ROOT'] : __DIR__;
$resolvedDocRoot = realpath($rawDocRoot);
$docRoot = rtrim(($resolvedDocRoot === false ? $rawDocRoot : $resolvedDocRoot), '/');
$scriptDir = realpath(__DIR__);
if ($scriptDir === false) {
    $scriptDir = __DIR__;
}
$relScriptDir = ($scriptDir === $docRoot) ? '' : ltrim(str_replace($docRoot, '', $scriptDir), '/');

// Backup artifacts live in "tmp/" — a sibling of the docroot every
// ISPConfig FTP account has (confirmed live) — NOT anywhere under
// $docRoot: writing the growing .tar.gz inside the tree tar is archiving
// raced against its own output regardless of --exclude (confirmed live:
// "tar: ...: file changed as we read it"). mini-download.php computes this
// same path independently (it can't rely on a relative path from itself,
// since it no longer lives next to the backup dir).
/**
 * Where backup artifacts go. Duplicated VERBATIM in mini-backup.php and
 * mini-download.php — they are deployed independently and cannot share an
 * include, and mini-download has to recompute the same answer from the same
 * inputs to find the archive. Keep the two copies identical.
 *
 * Ordered, and every candidate is tested for writability rather than assumed:
 *
 *   1. "<parent of docroot>/tmp/.wru-backup" — every ISPConfig FTP account has
 *      a tmp/ sibling of web/ (confirmed live), and this is the original
 *      behaviour, kept first so existing hosts are unaffected.
 *   2. "<parent of docroot>/.wru-backup" — a parent that is writable but has no
 *      tmp/.
 *   3. the system temp dir — outside the web tree entirely.
 *   4. "<docroot>/.wru-backup" — LAST resort, and the only candidate inside the
 *      tree tar is archiving, which is why it is last: writing the growing
 *      .tar.gz inside that tree races tar against its own output regardless of
 *      --exclude (confirmed live: "tar: ...: file changed as we read it").
 *
 * The hardcoded (1) was an ISPConfig assumption written into a script that also
 * runs against customer-owned hosts. On a reg.ru account the docroot is
 * "www/<domain>", so (1) resolves to "www/tmp/" — a directory that need not
 * exist and need not be writable.
 */
function wruBackupDir($docRoot)
{
    $parent = dirname($docRoot);
    $candidates = array(
        $parent . '/tmp/.wru-backup',
        $parent . '/.wru-backup',
        rtrim(sys_get_temp_dir(), '/') . '/.wru-backup-' . substr(md5($docRoot), 0, 8),
        $docRoot . '/.wru-backup',
    );
    foreach ($candidates as $dir) {
        if (!is_dir($dir)) {
            @mkdir($dir, 0755, true);
        }
        if (is_dir($dir) && is_writable($dir)) {
            return $dir;
        }
    }
    // Nothing was writable. Return the first candidate so the caller fails with
    // its own clear error about that path rather than on an empty string.
    return $candidates[0];
}

$backupDirName = '.wru-backup';
$backupDir = wruBackupDir($docRoot);

if (!function_exists('exec')) {
    echo json_encode(array('ok' => false, 'error' => 'exec() is disabled on this host — cannot shell out to tar/mysqldump'));
    exit;
}

// State files the detached runner writes, and ?action=status reads. Kept in
// the backup dir alongside the artifacts so one cleanup removes everything.
$stampFile = $backupDir . '/current.stamp';
$runner = $backupDir . '/run.sh';
$tarCodeFile = $backupDir . '/tar.code';
$sqlCodeFile = $backupDir . '/sql.code';
$tarOutFile = $backupDir . '/tar.out';
$sqlErrFile = $backupDir . '/sql.err';
$doneFile = $backupDir . '/done';

/**
 * Ordered connection-argument candidates for the mysql/mysqldump/mysqlcheck
 * clients. Duplicated verbatim in mini-restore.php — these scripts are
 * deployed independently of one another, so they cannot share an include.
 *
 * "localhost" is not one thing: to the CLIENT it usually means the UNIX
 * socket, but some client builds resolve it and open TCP to 127.0.0.1 instead
 * — and to the SERVER'S grant tables 'localhost' and '127.0.0.1' are two
 * different hosts. ISPConfig grants per-site users as user@'localhost' only,
 * so a client that quietly switches to TCP is refused with
 * "1130 - Host '127.0.0.1' is not allowed to connect". Confirmed live:
 * identical arguments worked on s12 and failed on s19.
 */
function wruMysqlConnAttempts($host, $port)
{
    $isLocal = ($host === '' || $host === 'localhost' || $host === '127.0.0.1' || $host === '::1');
    $tcpHost = $isLocal ? '127.0.0.1' : $host;
    $tcp = '--protocol=tcp -h ' . escapeshellarg($tcpHost) . ' -P ' . escapeshellarg($port);

    $attempts = array();
    // Socket first where it can exist: to MySQL a Unix socket counts as a secure
    // channel, which matters below.
    //
    // The default socket path is a client compile-time setting and frequently
    // does not match where the server actually put it, so the common locations
    // are tried explicitly. This matters more than it looks: when a server has
    // NEITHER TLS (error 2026: "SSL is required but the server doesn't support
    // it") NOR an RSA keypair for caching_sha2_password, the socket is the only
    // channel the auth plugin will accept at all.
    if ($isLocal) {
        $attempts['unix socket (default path)'] = '--protocol=socket';
        foreach (array(
            '/var/run/mysqld/mysqld.sock',
            '/var/lib/mysql/mysql.sock',
            '/tmp/mysql.sock',
            '/var/run/mysql/mysql.sock',
            '/var/lib/mysqld/mysqld.sock',
        ) as $sock) {
            $attempts['unix socket ' . $sock] = '--protocol=socket --socket=' . escapeshellarg($sock);
        }
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

/** Shell that archives the docroot as 2047 MB parts (name.tar.gz.000, .001, ...).
 *
 * One 12 GB file cannot be resumed or re-fetched piecemeal: a fetch that ended
 * mid-way and was resumed produced a file of exactly the right size and the
 * wrong sha256, and the only remedy was fetching all 12 GB again. Parts are
 * checked one by one, so a bad one costs one part. 2047 MiB stays under 2 GiB,
 * the limit of the older 32-bit tools on some hosts.
 *
 * The tar exit status is taken inside the pipeline's subshell, because a
 * pipeline reports the status of split, not of tar. Where split cannot number
 * its output the old single file is written instead. */
function wruTarShell($excludeArgs, $archivePath, $docRoot, $tarOutFile, $tarCodeFile)
{
    $sh  = 'if split --help 2>&1 | grep -q -- "--numeric-suffixes"; then' . "\n";
    $sh .= '  ( tar' . $excludeArgs . ' -czf - -C ' . escapeshellarg($docRoot) . ' . 2> ' . escapeshellarg($tarOutFile) .
        '; echo $? > ' . escapeshellarg($tarCodeFile) . ' ) | split -b 2047m -d -a 3 - ' . escapeshellarg($archivePath . '.') . "\n";
    $sh .= 'else' . "\n";
    $sh .= '  tar' . $excludeArgs . ' -czf ' . escapeshellarg($archivePath) .
        ' -C ' . escapeshellarg($docRoot) . ' . > ' . escapeshellarg($tarOutFile) . " 2>&1\n";
    $sh .= '  echo $? > ' . escapeshellarg($tarCodeFile) . "\n";
    $sh .= 'fi' . "\n";
    return $sh;
}

/** One full pass through every connection-transport candidate, retrying only
 * on a transport-level failure. Factored out so the --routines/--events
 * fallback below can reuse it with a different $dumpBase. */
function wruBuildDumpAttemptsShell($attempts, $dumpBase, $dumpTail, $dbPass, $errFile, $labelPrefix = '')
{
    $connRegex = 'is not allowed to connect|Access denied|Can.t connect|Authentication requires secure connection|caching_sha2_password|Lost connection to MySQL server|Unknown MySQL server host|unknown option|unknown variable';
    $sh = '';
    $first = true;
    foreach ($attempts as $label => $connArgs) {
        $marker = 'echo "--- attempt: ' . str_replace('"', '', $labelPrefix . $label) . '" >> ' . escapeshellarg($errFile) . "\n";
        if ($first) {
            $sh .= $marker;
            $sh .= 'MYSQL_PWD=' . escapeshellarg($dbPass) . ' ' . $dumpBase . ' ' . $connArgs . $dumpTail . "\n";
            $sh .= 'DUMPRC=$?' . "\n";
            $first = false;
            continue;
        }
        // Retry only on a connection-level refusal. Any other failure (bad
        // SQL, crashed table, disk full) fails identically over the other
        // transport, and retrying would just rewrite a half-finished dump.
        $sh .= 'if [ $DUMPRC -ne 0 ] && grep -qiE ' . escapeshellarg($connRegex) . ' ' . escapeshellarg($errFile) . ' 2>/dev/null; then' . "\n";
        $sh .= '  ' . $marker;
        $sh .= '  MYSQL_PWD=' . escapeshellarg($dbPass) . ' ' . $dumpBase . ' ' . $connArgs . $dumpTail . "\n";
        $sh .= '  DUMPRC=$?' . "\n";
        $sh .= 'fi' . "\n";
    }
    return $sh;
}

/**
 * Collects every symlink under $dir, recording its target verbatim.
 *
 * Never recurses INTO a symlinked directory: the target is not part of this
 * site's own tree (that is the entire point of recording it separately), and
 * following links invites cycles.
 *
 * $base is the realpath'd docroot, used to express each hit as a docroot-relative
 * path and to decide whether its target stays inside the site or escapes it.
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
                // An ABSOLUTE target cannot survive a move: ISPConfig hands out
                // different client/web numbers on the destination, so the old
                // path simply does not exist there. It has to be rewritten.
                'absolute' => ($target !== false && substr($target, 0, 1) === '/'),
                'resolved' => ($resolved === false) ? null : $resolved,
                // Inside the docroot -> the archive carries the target too and
                // the link keeps working. Outside -> the target is NOT in this
                // site's archive and the link needs repointing at whatever the
                // sister site becomes on the destination.
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

$action = isset($_GET['action']) ? $_GET['action'] : 'start';

/**
 * Read-only inventory of the docroot's symlinks.
 *
 * Needed for a Bitrix MULTISITE, where several sites share one Bitrix kernel:
 * the sister sites hold `bitrix` (and often `upload`) as symlinks into the main
 * site's docroot. tar stores such a link verbatim and does NOT archive its
 * target (verified), so restoring a sister site on its own yields a dangling
 * link and a site that cannot boot. Recording the links here is what makes it
 * possible to recreate them — repointed at the sister/main site's NEW path —
 * on the destination.
 */
if ($action === 'symlinks') {
    $links = array();
    wruCollectSymlinks($docRoot, $docRoot, $links, 0);
    $outside = 0;
    $absolute = 0;
    $dangling = 0;
    foreach ($links as $l) {
        if (!$l['inside_docroot']) {
            $outside++;
        }
        if ($l['absolute']) {
            $absolute++;
        }
        if ($l['dangling']) {
            $dangling++;
        }
    }
    echo json_encode(array(
        'ok' => true,
        'docroot' => $docRoot,
        'count' => count($links),
        'truncated' => (count($links) >= 500),
        'needing_rewrite' => $outside,
        'absolute' => $absolute,
        'dangling' => $dangling,
        'links' => $links,
    ));
    exit;
}

// Reports on the detached run without blocking. Returns whatever is known so
// far — the caller polls this and can show real progress (the archive's size
// grows as tar writes it) instead of staring at a request that may or may not
// still be alive.
if ($action === 'status') {
    $stamp = @file_get_contents($stampFile);
    if ($stamp === false || trim($stamp) === '') {
        echo json_encode(array('ok' => false, 'error' => 'no backup has been started'));
        exit;
    }
    $stamp = trim($stamp);
    $archiveName = 'wru-backup-' . $stamp . '.tar.gz';
    $sqlName = 'wru-backup-' . $stamp . '.sql';
    $archivePath = $backupDir . '/' . $archiveName;
    $sqlPath = $backupDir . '/' . $sqlName;

    $tarCode = is_file($tarCodeFile) ? trim(file_get_contents($tarCodeFile)) : null;
    $sqlCode = is_file($sqlCodeFile) ? trim(file_get_contents($sqlCodeFile)) : null;
    $done = is_file($doneFile);

    $tarOut = is_file($tarOutFile) ? trim(file_get_contents($tarOutFile)) : '';
    $sqlErr = is_file($sqlErrFile) ? trim(file_get_contents($sqlErrFile)) : '';

    // A split archive is name.tar.gz.000, .001, ...; the single file is the
    // fallback for a host whose split cannot number its output. Parts exist
    // while tar is still running (the last one partial), so a caller only uses
    // the list once `done` is set.
    $archiveParts = array();
    $archiveSize = wru_filesize($archivePath);
    $partPaths = @glob($archivePath . '.[0-9][0-9][0-9]');
    if (is_array($partPaths) && count($partPaths) > 0) {
        sort($partPaths);
        $total = 0;
        foreach ($partPaths as $partPath) {
            $partSize = wru_filesize($partPath);
            $archiveParts[] = array('name' => basename($partPath), 'size' => $partSize);
            $total += (float) $partSize;
        }
        $archiveSize = sprintf('%.0f', $total);
    }
    $sqlSize = wru_filesize($sqlPath);

    // "Finished" is the runner's own done marker, not just the presence of
    // output files — a growing archive looks exactly like a finished one from
    // the outside, and that ambiguity is what produced the 0-byte SQL dump
    // being treated as a completed backup before.
    $archiveOk = ($tarCode === '0') && $archiveSize > 0;
    $wantsSql = $WRU_DB_NAME !== '';
    $sqlOk = !$wantsSql || (($sqlCode === '0') && $sqlSize > 0);

    if ($done) {
        // The runner file holds the DB password on a command line; remove it
        // (and the stamp pointer) as soon as it can no longer be needed.
        @unlink($runner);
    }

    echo json_encode(array(
        'ok' => true,
        'done' => $done,
        'stamp' => $stamp,
        'archive' => array('name' => $archiveName, 'size' => $archiveSize, 'code' => $tarCode, 'parts' => $archiveParts),
        'sql' => $wantsSql ? array('name' => $sqlName, 'size' => $sqlSize, 'code' => $sqlCode) : null,
        'success' => $done && $archiveOk && $sqlOk,
        'tar_output' => $tarOut,
        'db_output' => $sqlErr,
    ));
    exit;
}

// Detached checksum of one wru-backup-* file. A 12 GB archive takes longer to
// hash than the web server lets one request live, so the hash runs under nohup
// and the caller polls hash_status. The size check alone cannot tell a
// byte-exact copy from one that is the right length and wrong inside.
if ($action === 'hash_start') {
    if (!function_exists('shell_exec')) {
        echo json_encode(array('ok' => false, 'error' => 'shell_exec() is disabled - cannot detach a checksum'));
        exit;
    }
    $name = isset($_POST['name']) ? basename($_POST['name']) : '';
    if (!preg_match('/^wru-backup-[0-9]{14}\.(tar\.gz(\.[0-9]{3})?|sql)$/', $name)) {
        echo json_encode(array('ok' => false, 'error' => 'invalid filename'));
        exit;
    }
    $path = $backupDir . '/' . $name;
    if (!is_file($path)) {
        echo json_encode(array('ok' => false, 'error' => 'file not found: ' . $name));
        exit;
    }
    $algo = (isset($_POST['algo']) && $_POST['algo'] === 'sha1') ? 'sha1' : 'sha256';
    $tool = $algo . 'sum';
    $probe = array();
    $probeCode = 1;
    @exec('command -v ' . $tool . ' 2>/dev/null', $probe, $probeCode);
    if ($probeCode !== 0) {
        echo json_encode(array('ok' => false, 'error' => $tool . ' is not installed on this host'));
        exit;
    }
    $out = $path . '.hash';
    $doneMarker = $path . '.hash.done';
    @unlink($out);
    @unlink($doneMarker);
    $cmd = 'nohup sh -c ' . escapeshellarg(
        $tool . ' ' . escapeshellarg($path) . ' > ' . escapeshellarg($out) . ' 2>&1; echo $? > ' . escapeshellarg($doneMarker)
    ) . ' > /dev/null 2>&1 & echo $!';
    $pid = trim(shell_exec($cmd));
    echo json_encode(array('ok' => true, 'pid' => $pid, 'name' => $name, 'algo' => $algo));
    exit;
}

if ($action === 'hash_status') {
    $name = isset($_POST['name']) ? basename($_POST['name']) : '';
    if (!preg_match('/^wru-backup-[0-9]{14}\.(tar\.gz(\.[0-9]{3})?|sql)$/', $name)) {
        echo json_encode(array('ok' => false, 'error' => 'invalid filename'));
        exit;
    }
    $path = $backupDir . '/' . $name;
    $out = $path . '.hash';
    $doneMarker = $path . '.hash.done';
    if (!is_file($doneMarker)) {
        echo json_encode(array('ok' => true, 'done' => false));
        exit;
    }
    $rc = trim(file_get_contents($doneMarker));
    $text = is_file($out) ? trim(file_get_contents($out)) : '';
    $parts = preg_split('/\s+/', $text);
    $hash = isset($parts[0]) ? strtolower($parts[0]) : '';
    if ($rc === '0' && preg_match('/^[0-9a-f]{40}$|^[0-9a-f]{64}$/', $hash)) {
        echo json_encode(array('ok' => true, 'done' => true, 'hash' => $hash, 'size' => wru_filesize($path)));
    } else {
        echo json_encode(array('ok' => false, 'done' => true, 'error' => 'checksum tool failed (exit ' . $rc . '): ' . substr($text, 0, 200)));
    }
    exit;
}

// Repairs crashed tables in this site's own database. Kept as a SEPARATE,
// explicitly-invoked action rather than something the backup does on its own:
// it mutates a live production database, and REPAIR TABLE on a crashed MyISAM
// table can drop unrecoverable rows. The caller decides.
//
// Needed because a single crashed table aborts the whole dump — seen live:
// "Table './c9_icinfo/b_forum_stat' is marked as crashed and should be
// repaired when using LOCK TABLES", which is pre-existing corruption on the
// source, not anything the migration caused.
if ($action === 'repair') {
    if (!function_exists('exec')) {
        echo json_encode(array('ok' => false, 'error' => 'exec() is disabled on this host — cannot shell out to mysqlcheck'));
        exit;
    }
    if ($WRU_DB_NAME === '') {
        echo json_encode(array('ok' => false, 'error' => 'no database configured for this deployment'));
        exit;
    }
    $dbHostR = $WRU_DB_HOST !== '' ? $WRU_DB_HOST : 'localhost';
    $dbPortR = $WRU_DB_PORT !== '' ? $WRU_DB_PORT : '3306';
    // Socket first, then TCP — see wruMysqlConnAttempts for why "-h localhost"
    // is not enough on its own.
    $out = array();
    $code = 1;
    foreach (wruMysqlConnAttempts($dbHostR, $dbPortR) as $label => $connArgs) {
        $cmd = 'MYSQL_PWD=' . escapeshellarg($WRU_DB_PASS) . ' mysqlcheck --repair ' . $connArgs .
            ' -u ' . escapeshellarg($WRU_DB_USER) .
            ' ' . escapeshellarg($WRU_DB_NAME) . ' 2>&1';
        $out = array();
        $code = 0;
        exec($cmd, $out, $code);
        if ($code === 0) {
            $out[] = '(connected via ' . $label . ')';
            break;
        }
        $joined = implode("\n", $out);
        if (!wruIsTransportError($joined)) {
            break;
        }
    }
    echo json_encode(array('ok' => ($code === 0), 'exit_code' => $code, 'output' => implode("\n", $out)));
    exit;
}

if ($action !== 'start') {
    echo json_encode(array('ok' => false, 'error' => 'unknown action'));
    exit;
}

$stamp = date('YmdHis');
$archiveName = 'wru-backup-' . $stamp . '.tar.gz';
$archivePath = $backupDir . '/' . $archiveName;

// Only the deployed script itself needs excluding now — the backup
// directory lives entirely outside $docRoot, so no race with it is
// possible. Exclude path is relative to $docRoot (the tar -C target), not
// to __DIR__ — when the script lives in a subdirectory, that means e.g.
// "public/wru_xxx.php", not just the bare filename.
$selfRelPath = ($relScriptDir !== '' ? $relScriptDir . '/' : '') . basename(__FILE__);

// Extra excludes supplied by the caller (JSON array of docroot-relative
// paths). Deliberately caller-driven: which directories are regenerable junk
// is framework knowledge, and this file holds none. Anything with a path
// traversal or an absolute path is refused rather than silently passed to
// tar.
$excludeArgs = ' --exclude=' . escapeshellarg($selfRelPath);
$excludesRaw = isset($_POST['excludes']) ? $_POST['excludes'] : (isset($_GET['excludes']) ? $_GET['excludes'] : '');
$excludesApplied = array();
if ($excludesRaw !== '') {
    $decoded = json_decode($excludesRaw, true);
    if (is_array($decoded)) {
        foreach ($decoded as $ex) {
            if (!is_string($ex) || $ex === '') {
                continue;
            }
            if (strpos($ex, '..') !== false || substr($ex, 0, 1) === '/') {
                continue;
            }
            $excludeArgs .= ' --exclude=' . escapeshellarg('./' . ltrim($ex, './'));
            $excludesApplied[] = $ex;
        }
    }
}

$dbHost = $WRU_DB_HOST !== '' ? $WRU_DB_HOST : 'localhost';
$dbPort = $WRU_DB_PORT !== '' ? $WRU_DB_PORT : '3306';
$sqlName = $WRU_DB_NAME !== '' ? 'wru-backup-' . $stamp . '.sql' : null;

// Clear any previous run's state so ?action=status can't report a stale
// result as if it belonged to this one.
foreach (array($tarCodeFile, $sqlCodeFile, $tarOutFile, $sqlErrFile, $doneFile) as $f) {
    @unlink($f);
}

// Purge previous runs' artifacts. Without this each re-run leaves another
// full copy of the site behind: a real 4.0 GB archive from a failed attempt
// was still sitting here when the next backup started, and nothing would ever
// have removed it. Strictly pattern-matched, and only inside this script's
// own backup directory.
$purged = array();
$existing = @glob($backupDir . '/wru-backup-*');
if (is_array($existing)) {
    foreach ($existing as $old) {
        if (preg_match('/wru-backup-[0-9]{14}\.(tar\.gz(\.[0-9]{3})?|sql)(\.hash(\.done)?)?$/', $old) && @unlink($old)) {
            $purged[] = basename($old);
        }
    }
}

// The runner script, executed detached. Each step records its own exit code
// the instant it finishes, and the "done" marker is written last — so status
// can always distinguish "still running" from "finished, and here's how it
// went" without guessing from file sizes.
$sh = "#!/bin/sh\n";
$sh .= 'cd ' . escapeshellarg($backupDir) . " || exit 1\n";
if ($sqlName !== null) {
    $sqlPath = $backupDir . '/' . $sqlName;
    // MYSQL_PWD rather than -p on the command line: the password would
    // otherwise be visible to any local user via `ps` for the whole dump.
    // --no-tablespaces: mysqldump 5.7+/8.0 queries INFORMATION_SCHEMA.FILES
    // by default, which needs the global PROCESS privilege that a per-site
    // hosting DB user does not have. Confirmed live: without it the dump
    // aborts with "Access denied; you need (at least one of) the PROCESS
    // privilege(s) ... when trying to dump tablespaces". Nothing is lost —
    // tablespace DDL is irrelevant to a per-database logical dump.
    // --default-character-set=binary --skip-set-charset: dump the stored
    // BYTES verbatim, with no charset conversion and no SET NAMES header, and
    // import the same way (see mini-restore.php). The alternative — letting
    // mysqldump convert to utf8 on the way out and back on the way in — only
    // round-trips cleanly when every column's declared charset matches what
    // the bytes really are, which is exactly what can't be assumed on a
    // legacy site. This source is cp1251 (its own bitrix/php_interface/
    // after_connect_d7.php runs SET NAMES 'cp1251' and .settings.php has
    // utf_mode => false), and double-encoded rows are a common way for such
    // sites to end up "wrong but consistent" — a converting dump silently
    // mangles those, a byte-exact one cannot. CREATE TABLE still carries each
    // table's own DEFAULT CHARSET, so the destination ends up byte-identical.
    // Socket-then-TCP, expressed in SHELL rather than as a PHP retry loop:
    // this command runs inside the detached runner, long after this request
    // has returned, so PHP is not around to retry it. Same reasoning as
    // wruMysqlConnAttempts — "-h localhost" is not a reliable way to get the
    // socket, and ISPConfig grants user@'localhost' (socket) not
    // user@'127.0.0.1'.
    // --routines --events: --opt does not enable these (unlike --triggers),
    // so stored procedures/functions/events were silently dropped before.
    $dumpBase = 'mysqldump --opt --no-tablespaces $WRU_CS --default-character-set=binary --skip-set-charset --routines --events';
    // Fallback used only if the dump above fails outright -- see below.
    $dumpBaseFallback = 'mysqldump --opt --no-tablespaces $WRU_CS --default-character-set=binary --skip-set-charset';
    // 2>> (append), not 2> (truncate).
    //
    // Every attempt wrote to the same error file with >, so each one erased the
    // last and only the final attempt's message survived. That made a four-step
    // fallback chain look like a single failure: "SSL is required but the server
    // doesn't support it" was reported while the reason the socket and the
    // public-key attempts failed — the actually useful information — had been
    // overwritten. A label per attempt goes in first.
    $dumpTail = ' -u ' . escapeshellarg($WRU_DB_USER) .
        ' ' . escapeshellarg($WRU_DB_NAME) .
        ' > ' . escapeshellarg($sqlPath) . ' 2>> ' . escapeshellarg($sqlErrFile);
    $attempts = wruMysqlConnAttempts($dbHost, $dbPort);
    // mysqldump 8.0 reads information_schema.COLUMN_STATISTICS, which a MySQL 5.x or
    // MariaDB server does not have, and aborts the dump. Only a mysqldump that
    // knows the option may be given it: MariaDB's rejects it as an unknown option.
    $sh .= 'WRU_CS=""; if mysqldump --help 2>/dev/null | grep -q -- "--column-statistics"; then WRU_CS="--column-statistics=0"; fi' . "\n";
    $sh .= ': > ' . escapeshellarg($sqlErrFile) . "\n";
    $sh .= wruBuildDumpAttemptsShell($attempts, $dumpBase, $dumpTail, $WRU_DB_PASS, $sqlErrFile);
    // A missing SHOW_ROUTINE/EVENT grant fails the WHOLE dump, not just the
    // routines -- retry once without them rather than lose the tables too.
    $sh .= 'if [ $DUMPRC -ne 0 ]; then' . "\n";
    $sh .= '  echo "--- dump with --routines/--events failed (exit $DUMPRC) -- retrying without them ---" >> ' . escapeshellarg($sqlErrFile) . "\n";
    $sh .= wruBuildDumpAttemptsShell($attempts, $dumpBaseFallback, $dumpTail, $WRU_DB_PASS, $sqlErrFile, 'fallback: ');
    $sh .= 'fi' . "\n";
    $sh .= 'echo $DUMPRC > ' . escapeshellarg($sqlCodeFile) . "\n";
}

// The archive is created LAST, and only if the dump worked.
//
// Order matters for how quickly a failure is discovered. The database dump takes
// seconds; the archive took eight minutes and 494 MB on polimer-paket.ru. With
// tar first, a rejected database login was reported after the whole site had been
// archived — twice — and the archive was then useless anyway, since a CMS
// restored without its database is not a restore. Bitrix's own backup does the
// database first for the same reason.
//
// The guard is $DUMPRC when there was a dump to run, and unconditional when
// there is no database at all (a genuinely static site still needs its files).
if ($sqlName !== null) {
    $sh .= 'if [ $DUMPRC -eq 0 ]; then' . "\n";
    $sh .= '  tar' . $excludeArgs . ' -czf ' . escapeshellarg($archivePath) .
        ' -C ' . escapeshellarg($docRoot) . ' . > ' . escapeshellarg($tarOutFile) . " 2>&1\n";
    $sh .= '  echo $? > ' . escapeshellarg($tarCodeFile) . "\n";
    $sh .= 'else' . "\n";
    // A code file the status action can read, so "skipped" is reported as such
    // rather than as a tar that silently never ran.
    $sh .= '  echo skipped-db-failed > ' . escapeshellarg($tarCodeFile) . "\n";
    $sh .= '  echo "tar skipped: the database dump failed, so the archive would be useless" > ' .
        escapeshellarg($tarOutFile) . "\n";
    $sh .= 'fi' . "\n";
} else {
    $sh .= 'tar' . $excludeArgs . ' -czf ' . escapeshellarg($archivePath) .
        ' -C ' . escapeshellarg($docRoot) . ' . > ' . escapeshellarg($tarOutFile) . " 2>&1\n";
    $sh .= 'echo $? > ' . escapeshellarg($tarCodeFile) . "\n";
}
$sh .= 'touch ' . escapeshellarg($doneFile) . "\n";

if (@file_put_contents($runner, $sh) === false) {
    echo json_encode(array('ok' => false, 'error' => 'could not write the runner script'));
    exit;
}
// 0700 before it ever holds a password-bearing command line.
@chmod($runner, 0700);
@file_put_contents($stampFile, $stamp);

// Detached: redirecting all three streams and backgrounding is what lets
// exec() return immediately instead of waiting for tar+mysqldump.
//
// setsid where available, so the runner gets its own session rather than
// staying in the request's process group. Rationale, not a diagnosis: what
// actually killed the earlier mysqldump was never pinned down, and nohup
// alone only ignores SIGHUP — it would not survive the SIGTERM/SIGKILL a
// process-group cleanup sends. setsid covers that case too, so it's the
// safer default regardless of which mechanism was really at fault.
// The availability probe is a SEPARATE exec rather than a `&&`/`||` chain
// around the launcher: `cmd &` followed by `||` is a shell syntax error, and
// as written that meant the backup silently never started at all (caught by a
// local end-to-end test — the error went to the launcher's own discarded
// output, so the JSON still cheerfully said "started": true).
$probe = array();
$probeCode = 1;
@exec('command -v setsid 2>/dev/null', $probe, $probeCode);
$launcher = 'sh ' . escapeshellarg($runner) . ' > /dev/null 2>&1 &';
exec(($probeCode === 0 ? 'setsid ' : 'nohup ') . $launcher);

echo json_encode(array(
    'ok' => true,
    'started' => true,
    'stamp' => $stamp,
    'archive' => array('name' => $archiveName),
    'sql' => $sqlName !== null ? array('name' => $sqlName) : null,
    'excludes_applied' => $excludesApplied,
    'purged' => $purged,
));
