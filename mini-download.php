<?php
/**
 * wr-util mini download helper — streams one file out of the .wru-backup
 * directory mini-backup.php wrote (in "tmp/", a sibling of the docroot,
 * not next to this script — see mini-backup.php's comment on why: writing
 * inside the docroot raced tar against its own output). Same deploy-time
 * templating as mini-backup.php (random filename, __WRU_TOKEN__ replaced
 * before upload) — see wr-util's miniScriptClient.ts.
 *
 * PHP 5.2/5.3-compatible syntax only, same reasoning as mini-backup.php.
 */

// Critical here specifically: this script streams a raw tar.gz/SQL body, so an
// inline PHP warning is prepended straight into the downloaded bytes and
// silently corrupts the archive. See mini-backup.php's matching note.
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


$WRU_TOKEN = '__WRU_TOKEN__';

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
 * site's plaintext HTTP access log on every single call.
 *
 * This file is fetched SERVER-TO-SERVER by mini-restore.php's `fetch` action,
 * which is handed only a URL. That is why fetch now forwards an explicit
 * header (see its `auth_header` parameter) rather than the caller smuggling
 * the token into the query string, which was the only way it could work
 * before.
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

// Deadline first, before anything else answers.
if (wru_expired($WRU_DEADLINE)) {
    header('HTTP/1.1 410 Gone');
    header('Content-Type: application/json');
    echo json_encode(array('ok' => false, 'error' => 'this helper has expired; redeploy it'));
    exit;
}

// Liveness probe: carries NO token and reveals nothing but its own existence.
if (isset($_GET['ping'])) {
    header('Content-Type: application/json');
    echo json_encode(array('ok' => true, 'ping' => true));
    exit;
}

$wru_token = wru_request_token();
if ($wru_token === '' || $wru_token !== $WRU_TOKEN) {
    header('HTTP/1.1 403 Forbidden');
    header('Content-Type: application/json');
    echo json_encode(array('ok' => false, 'error' => 'forbidden'));
    exit;
}

$file = isset($_GET['file']) ? $_GET['file'] : '';
// Filename only — no path separators, no traversal. mini-backup.php only
// ever generates names matching this shape.
if ($file === '' || !preg_match('/^wru-backup-[0-9]{14}\.(tar\.gz(\.[0-9]{3})?|sql)$/', $file)) {
    header('HTTP/1.1 400 Bad Request');
    header('Content-Type: application/json');
    echo json_encode(array('ok' => false, 'error' => 'invalid filename'));
    exit;
}

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

$docRoot = rtrim((isset($_SERVER['DOCUMENT_ROOT']) && $_SERVER['DOCUMENT_ROOT'] !== '' ? $_SERVER['DOCUMENT_ROOT'] : __DIR__), '/');
$backupDir = wruBackupDir($docRoot);
$path = $backupDir . '/' . $file;
// Existence is decided by wru_filesize(), NOT by is_file().
//
// On a 32-bit host is_file() returns false for any file larger than 2 GB, so
// this guard used to 404 on exactly the archives this script exists to serve —
// and the caller reported only "mini-restore fetch failed: curl: (22) The
// requested URL returned error: 404", which reads as a missing file or a bad
// URL rather than a working file that PHP cannot stat.
//
// Confirmed live on legacy3.wr0.ru (PHP 5.3.29, PHP_INT_MAX 2147483647, i.e.
// 32-bit) with a 3,254,286,263-byte archive sitting in the staging directory:
// is_file() false, filesize() false, `stat -c %s` correct. The Range and
// Content-Length code below is already float-safe via sprintf('%.0f'), so this
// guard was the only thing standing in the way.
$size = wru_filesize($path);
if ($size === 0) {
    header('HTTP/1.1 404 Not Found');
    header('Content-Type: application/json');
    echo json_encode(array('ok' => false, 'error' => 'not found'));
    exit;
}
if (!is_numeric($size)) {
    // The file is openable but its size could not be established by any method,
    // so Range arithmetic and Content-Length would both be wrong. Fail loudly
    // instead of streaming a body of unknown length.
    header('HTTP/1.1 500 Internal Server Error');
    header('Content-Type: application/json');
    echo json_encode(array('ok' => false, 'error' => 'file present but size unmeasurable on this host'));
    exit;
}
$size = (float)$size;

// Range support, because a multi-GB transfer that dies at 80% must resume
// rather than start over. The destination's fetch may also probe with a small
// range first. Only the simple "bytes=start-[end]" form is handled -- that is
// all curl and the fetch step ever send.
$start = 0;
$end = $size - 1;
$isPartial = false;
if (isset($_SERVER['HTTP_RANGE']) && preg_match('/bytes=(\d*)-(\d*)/', $_SERVER['HTTP_RANGE'], $m)) {
    if ($m[1] !== '') {
        $start = (float)$m[1];
    }
    if ($m[2] !== '') {
        $end = (float)$m[2];
    }
    if ($start > $end || $start >= $size) {
        header('HTTP/1.1 416 Requested Range Not Satisfiable');
        header('Content-Range: bytes */' . sprintf('%.0f', $size));
        exit;
    }
    $isPartial = true;
}
$length = $end - $start + 1;

// Any buffering layer would try to accumulate the whole body in memory. That is
// what broke this: readfile() on a 6.6GB archive under memory_limit=512M
// returned a bare 500, so the destination's fetch failed with "curl: (22) ...
// error: 500" and nothing said why. Tear the buffers down before sending.
while (ob_get_level() > 0) {
    @ob_end_clean();
}
@set_time_limit(0);
@ini_set('memory_limit', '-1');
@ini_set('zlib.output_compression', '0');

if ($isPartial) {
    header('HTTP/1.1 206 Partial Content');
    header('Content-Range: bytes ' . sprintf('%.0f', $start) . '-' . sprintf('%.0f', $end) . '/' . sprintf('%.0f', $size));
}
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . $file . '"');
header('Accept-Ranges: bytes');
// sprintf %.0f rather than plain concatenation: sizes above 2^31 print in
// scientific notation on some builds, and a Content-Length of "6.7732e+09"
// makes the client abandon the transfer.
header('Content-Length: ' . sprintf('%.0f', $length));

$fh = fopen($path, 'rb');
if ($fh === false) {
    header('HTTP/1.1 500 Internal Server Error');
    exit;
}
if ($start > 0) {
    // fseek takes an int; for offsets past 2GB seek in steps so this still works
    // where PHP_INT_MAX would otherwise be exceeded by the cast.
    fseek($fh, 0, SEEK_SET);
    $remaining = $start;
    while ($remaining > 0) {
        $step = $remaining > 1073741824 ? 1073741824 : (int)$remaining;
        fseek($fh, $step, SEEK_CUR);
        $remaining -= $step;
    }
}
$sent = 0;
while ($sent < $length && !feof($fh)) {
    $chunk = $length - $sent;
    if ($chunk > 1048576) {
        $chunk = 1048576;
    }
    $data = fread($fh, (int)$chunk);
    if ($data === false || $data === '') {
        break;
    }
    echo $data;
    $sent += strlen($data);
    flush();
    // Stop burning CPU and disk if the client has gone away mid-transfer.
    if (connection_aborted()) {
        break;
    }
}
fclose($fh);
