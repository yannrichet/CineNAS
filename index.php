<?php
/**
 * SecureFileManager — single-file PHP file manager (PHP 5.6+ compatible)
 *
 * Les clés et secrets sont dans config.php (même répertoire).
 * Voir config.php pour les instructions de configuration.
 */

// ── Configuration ──────────────────────────────────────────────────────────────
$config_file = __DIR__ . DIRECTORY_SEPARATOR . 'config.php';
if (!file_exists($config_file)) {
    die('Fichier config.php manquant. Créez-le à partir de la documentation fournie.');
}
require $config_file;

define('FM_ROOT',          realpath(__DIR__));
define('FM_TITLE',         'CineNAS');
define('FM_MAX_UPLOAD_MB', 512);
define('FM_DEMO_MODE',     false);
define('FM_ALLOWED_EXT',   implode(',', array(
    'mkv','mp4','avi','mov','wmv','flv','mpg','mpeg','m4v','3gp','ts','webm',
    'jpg','jpeg','png','gif','webp','svg','ico','bmp',
    'mp3','aac','wav','flac','ogg','m4a',
    'pdf','txt','md','nfo','srt','sub','ass','ssa',
    'zip','rar','7z','tar','gz','bz2','iso',
)));

ini_set('upload_max_filesize', FM_MAX_UPLOAD_MB . 'M');
ini_set('post_max_size',       (FM_MAX_UPLOAD_MB + 4) . 'M');
session_start();

// ── CSRF ───────────────────────────────────────────────────────────────────────
function csrf_token() {
    if (empty($_SESSION['csrf'])) {
        if (function_exists('random_bytes')) {
            $_SESSION['csrf'] = bin2hex(random_bytes(32));
        } else {
            $_SESSION['csrf'] = bin2hex(openssl_random_pseudo_bytes(32));
        }
    }
    return $_SESSION['csrf'];
}
function csrf_check() {
    $token = isset($_POST['_csrf']) ? $_POST['_csrf'] : '';
    if (!hash_equals(csrf_token(), $token)) {
        http_response_code(403);
        die('CSRF validation failed.');
    }
}

// ── Auth ───────────────────────────────────────────────────────────────────────
function authed() { return !empty($_SESSION['fm']); }

$login_error = null;
if (isset($_POST['_login'])) {
    csrf_check();
    $pw = isset($_POST['pw']) ? $_POST['pw'] : '';
    if (password_verify($pw, FM_PASSWORD_HASH)) {
        $_SESSION['fm'] = true;
        $redirect = strtok($_SERVER['REQUEST_URI'], '?');
        header('Location: ' . $redirect);
        exit;
    }
    $login_error = 'Wrong password.';
}
if (isset($_GET['logout'])) {
    session_destroy();
    $redirect = strtok($_SERVER['REQUEST_URI'], '?');
    header('Location: ' . $redirect);
    exit;
}
if (!authed()) { render_login($login_error); exit; }

// ── Path safety ────────────────────────────────────────────────────────────────
function jail($rel) {
    // Normalize without resolving symlinks (realpath() would follow symlinks to
    // other mount points and fail the FM_ROOT prefix check)
    $raw   = FM_ROOT . DIRECTORY_SEPARATOR . ltrim($rel, '/\\');
    $parts = array();
    foreach (explode(DIRECTORY_SEPARATOR, str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $raw)) as $p) {
        if ($p === '..') { array_pop($parts); }
        elseif ($p !== '.' && $p !== '') { $parts[] = $p; }
    }
    $abs = DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $parts);
    if (strncmp($abs, FM_ROOT, strlen(FM_ROOT)) !== 0) return false;
    if (!file_exists($abs)) return false;
    return $abs;
}
function jail_new($rel) {
    $raw   = FM_ROOT . DIRECTORY_SEPARATOR . ltrim($rel, '/\\');
    $parts = array();
    foreach (explode(DIRECTORY_SEPARATOR, str_replace(array('/', '\\'), DIRECTORY_SEPARATOR, $raw)) as $p) {
        if ($p === '..') { array_pop($parts); }
        elseif ($p !== '.' && $p !== '') { $parts[] = $p; }
    }
    $abs = DIRECTORY_SEPARATOR . implode(DIRECTORY_SEPARATOR, $parts);
    if (strncmp($abs, FM_ROOT, strlen(FM_ROOT)) !== 0) return false;
    return $abs;
}
function relpath($abs) {
    return ltrim(substr($abs, strlen(FM_ROOT)), DIRECTORY_SEPARATOR);
}
function current_dir() {
    $dir = isset($_GET['dir']) ? $_GET['dir'] : '';
    $abs = jail($dir);
    if ($abs === false || !is_dir($abs)) return FM_ROOT;
    return $abs;
}

// ── File helpers ───────────────────────────────────────────────────────────────
function fmt_size($bytes) {
    // Use float to handle large files correctly on 32-bit PHP
    $b = (float)sprintf('%u', (int)$bytes);
    if ($b >= 1073741824) return round($b / 1073741824, 2) . ' GB';
    if ($b >= 1048576)    return round($b / 1048576, 1)    . ' MB';
    if ($b >= 1024)       return round($b / 1024, 1)       . ' KB';
    return $b . ' B';
}
function file_icon($ext) {
    $map = array(
        'mkv'=>'🎬','mp4'=>'🎬','avi'=>'🎬','mov'=>'🎬','wmv'=>'🎬','flv'=>'🎬',
        'mpg'=>'🎬','mpeg'=>'🎬','m4v'=>'🎬','webm'=>'🎬','ts'=>'🎬','3gp'=>'🎬',
        'mp3'=>'🎵','aac'=>'🎵','wav'=>'🎵','flac'=>'🎵','ogg'=>'🎵','m4a'=>'🎵',
        'jpg'=>'🖼','jpeg'=>'🖼','png'=>'🖼','gif'=>'🖼','webp'=>'🖼','svg'=>'🖼',
        'pdf'=>'📕','txt'=>'📝','md'=>'📝','nfo'=>'📝','srt'=>'📝','ass'=>'📝',
        'zip'=>'📦','rar'=>'📦','7z'=>'📦','tar'=>'📦','gz'=>'📦','bz2'=>'📦','iso'=>'📀',
    );
    return isset($map[$ext]) ? $map[$ext] : '📄';
}
function previewable($ext) {
    if (in_array($ext, array('jpg','jpeg','png','gif','webp','svg'), true)) return 'image';
    if (in_array($ext, array('mp4','webm','mkv','m4v'), true))             return 'video';
    if (in_array($ext, array('mp3','ogg','wav','aac','flac','m4a'), true)) return 'audio';
    if (in_array($ext, array('txt','md','nfo','srt','sub','ass','ssa'), true)) return 'text';
    if ($ext === 'pdf') return 'pdf';
    return '';
}
function breadcrumbs($rel) {
    $parts = array_values(array_filter(explode('/', $rel), function($p) { return $p !== ''; }));
    $html  = '<a href="?">🏠</a>';
    $path  = '';
    foreach ($parts as $p) {
        $path .= '/' . $p;
        $html .= ' <span class="sep">/</span> <a href="?dir=' . urlencode(ltrim($path, '/')) . '">' . h($p) . '</a>';
    }
    return $html;
}
function h($s) { return htmlspecialchars($s, ENT_QUOTES, 'UTF-8'); }
function safe_filename($name) {
    return preg_replace('/[^A-Za-z0-9._\-\(\) \[\]]/', '_', $name);
}

// ── Per-directory metadata helpers ─────────────────────────────────────────────
function meta_file_for($dir)    { return $dir . DIRECTORY_SEPARATOR . '.movies_meta.json'; }
function posters_dir_for($dir)  { return $dir . DIRECTORY_SEPARATOR . '.posters'; }
function posters_url_for($dir)  {
    // $dir comes from jail() which already roots the path at FM_ROOT —
    // avoid realpath() which can return a different path on NAS/symlink setups.
    $rel = ltrim(substr($dir, strlen(FM_ROOT)), DIRECTORY_SEPARATOR);
    $base = ($rel === '') ? '' : str_replace(DIRECTORY_SEPARATOR, '/', $rel) . '/';
    return $base . '.posters/';
}

// ── Movie metadata ─────────────────────────────────────────────────────────────
function meta_load($dir) {
    $f = meta_file_for($dir);
    if (!file_exists($f)) return array();
    $data = json_decode(file_get_contents($f), true);
    return is_array($data) ? $data : array();
}
function meta_save($data, $dir) {
    @file_put_contents(meta_file_for($dir), json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE));
}
function parse_movie_name($filename) {
    $name = pathinfo($filename, PATHINFO_FILENAME);
    $year = null;
    // Year with surrounding separator: (2017), .2017., _2017_, space2017space
    if (preg_match('/[\(\.\s_](\d{4})[\)\.\s_]/', $name, $m)) {
        $year = (int)$m[1];
    // Year at end of string with a separator before it
    } elseif (preg_match('/[\(\.\s_](\d{4})$/', $name, $m)) {
        $year = (int)$m[1];
    // Year directly concatenated at end (e.g. Flow2024, Sibyl2019)
    } elseif (preg_match('/((?:19|20)\d{2})$/', $name, $m)) {
        $year = (int)$m[1];
    }
    // Remove year + everything after (quality tags, etc.)
    $title = preg_replace('/[\(\[\.\s_](19|20)\d{2}[\)\]\.\s_].*$/i', '', $name);
    if ($title === $name) $title = preg_replace('/[\(\[\.\s_](19|20)\d{2}[\)\]\.\s_]?$/i', '', $name);
    if ($title === $name) $title = preg_replace('/(19|20)\d{2}$/i', '', $name);
    // Strip quality/source tags (space-separated or bracket-enclosed)
    $title = preg_replace('/[\[\(](blu.?ray|bdrip|dvdrip|webrip|web.?dl|hdtv|hdrip|xvid|divx|x264|x265|hevc|aac|ac3|dts|multi|vf|vff|vostfr|truefrench)[^\)]*[\]\)]/i', '', $title);
    $title = preg_replace('/\.(blu.?ray|dvdrip|bdrip|webrip|web.?dl|hdtv|1080p|720p|480p|2160p|4k|xvid|x264|x265|hevc).*/i', '', $title);
    $title = preg_replace('/[\s_]+(1080p|720p|480p|2160p|4k|vff|vf|vostfr|bluray|webrip|hdtv|bdrip|dvdrip|xvid|x264|x265|hevc|aac|ac3|dts|multi|truefrench).*/i', '', $title);
    // Replace dots and underscores with spaces
    $title = str_replace(array('.', '_'), ' ', $title);
    // Split CamelCase
    $title = preg_replace('/([a-z])([A-Z])/', '$1 $2', $title);
    $title = preg_replace('/\s{2,}/', ' ', $title);
    $title = trim($title);
    return array('title' => $title, 'year' => $year);
}
// Detects multi-part naming patterns (part1/cd1/disc1/d1 …) in a filename.
// Returns array('base'=>…, 'part'=>N) or null if not a known pattern.
function detect_movie_parts($filename) {
    $stem = pathinfo($filename, PATHINFO_FILENAME);
    if (preg_match('/^(.*?)[\.\-_ ](part|cd|disc|d)(\d+)$/i', $stem, $m)) {
        return array('base' => $m[1], 'part' => (int)$m[3]);
    }
    return null;
}
function tmdb_fetch($title, $year = null) {
    if (!FM_TMDB_API_KEY) return null;
    $query = urlencode($title);
    $url   = 'https://api.themoviedb.org/3/search/movie'
           . '?query=' . $query
           . '&language=' . FM_TMDB_LANG
           . ($year ? '&year=' . $year : '');
    $ctx  = stream_context_create(array('http' => array(
        'timeout' => 8,
        'ignore_errors' => true,
        'header' => 'Authorization: Bearer ' . FM_TMDB_API_KEY . "\r\n"
                  . 'Accept: application/json' . "\r\n",
    )));
    $resp = @file_get_contents($url, false, $ctx);
    if (!$resp) return null;
    $data = json_decode($resp, true);
    if (empty($data['results'])) {
        if ($year) return tmdb_fetch($title, null);
        return null;
    }
    $m = $data['results'][0];
    return array(
        'tmdb_id'     => $m['id'],
        'title'       => isset($m['title'])          ? $m['title']          : $title,
        'orig_title'  => isset($m['original_title']) ? $m['original_title'] : '',
        'year'        => isset($m['release_date'])   ? (int)substr($m['release_date'], 0, 4) : $year,
        'poster_path' => isset($m['poster_path'])    ? $m['poster_path']    : '',
        'rating'      => isset($m['vote_average'])   ? round($m['vote_average'], 1) : null,
        'votes'       => isset($m['vote_count'])     ? $m['vote_count']     : 0,
        'overview'    => isset($m['overview'])       ? $m['overview']       : '',
        'fetched_at'  => time(),
    );
}
function poster_download($poster_path, $dir) {
    if (!$poster_path) return '';
    $posters_dir = posters_dir_for($dir);
    $posters_url = posters_url_for($dir);
    if (!is_dir($posters_dir)) {
        @mkdir($posters_dir, 0755, true);
    }
    $local_name = md5($poster_path) . '.jpg';
    $local_path = $posters_dir . DIRECTORY_SEPARATOR . $local_name;
    if (file_exists($local_path)) {
        return $posters_url . $local_name;
    }
    $url = 'https://image.tmdb.org/t/p/w300' . $poster_path;
    $ctx = stream_context_create(array('http' => array('timeout' => 10)));
    $img = @file_get_contents($url, false, $ctx);
    if ($img) {
        @file_put_contents($local_path, $img);
        return $posters_url . $local_name;
    }
    return '';
}

function star_html($rating) {
    if ($rating === null) return '<span class="no-rating">—</span>';
    $pct = round(($rating / 10) * 100);
    return '<span class="stars" title="' . $rating . '/10">'
         . '<span class="stars-fill" style="width:' . $pct . '%">★★★★★</span>'
         . '<span class="stars-bg">★★★★★</span>'
         . '</span> <span class="rating-num">' . $rating . '</span>';
}

// ── Actions (POST) ─────────────────────────────────────────────────────────────
$msg = $err = '';
$action = isset($_POST['action']) ? $_POST['action'] : '';

// ── Download / Preview (GET) ──
$get_action = isset($_GET['action']) ? $_GET['action'] : '';
if ($get_action === 'download') {
    $f = jail(isset($_GET['file']) ? $_GET['file'] : '');
    if ($f && is_file($f)) {
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . addslashes(basename($f)) . '"');
        header('Content-Length: ' . filesize($f));
        header('Cache-Control: no-cache');
        readfile($f); exit;
    }
    http_response_code(404); exit;
}
if ($get_action === 'preview') {
    $f = jail(isset($_GET['file']) ? $_GET['file'] : '');
    if ($f && is_file($f)) {
        $ext  = strtolower(pathinfo($f, PATHINFO_EXTENSION));
        $mime_map = array(
            'jpg'=>'image/jpeg','jpeg'=>'image/jpeg','png'=>'image/png','gif'=>'image/gif',
            'webp'=>'image/webp','svg'=>'image/svg+xml',
            'mp4'=>'video/mp4','webm'=>'video/webm','mkv'=>'video/x-matroska','m4v'=>'video/mp4',
            'mp3'=>'audio/mpeg','ogg'=>'audio/ogg','wav'=>'audio/wav',
            'aac'=>'audio/aac','flac'=>'audio/flac','m4a'=>'audio/mp4',
            'txt'=>'text/plain','md'=>'text/plain','nfo'=>'text/plain',
            'srt'=>'text/plain','sub'=>'text/plain','ass'=>'text/plain','ssa'=>'text/plain',
            'pdf'=>'application/pdf',
        );
        $mime = isset($mime_map[$ext]) ? $mime_map[$ext] : 'application/octet-stream';
        header('Content-Type: ' . $mime);
        header('Content-Length: ' . filesize($f));
        header('Cache-Control: max-age=3600');
        readfile($f); exit;
    }
    http_response_code(404); exit;
}

// ── Cache poster sent by browser (AJAX, POST) ─────────────────────────────────
if ($get_action === 'cache_poster' && $_SERVER['REQUEST_METHOD'] === 'POST') {
    header('Content-Type: application/json');
    $filename = isset($_POST['file']) ? $_POST['file'] : '';
    if (!$filename || empty($_FILES['img']['tmp_name'])) { echo '{"ok":false}'; exit; }
    $ajax_cwd = current_dir();
    $meta = meta_load($ajax_cwd);
    if (!isset($meta[$filename]) || !empty($meta[$filename]['poster_local'])) { echo '{"ok":false}'; exit; }
    $poster_path = !empty($meta[$filename]['poster_path']) ? $meta[$filename]['poster_path'] : '';
    if (!$poster_path) { echo '{"ok":false}'; exit; }
    $posters_dir = posters_dir_for($ajax_cwd);
    if (!is_dir($posters_dir)) @mkdir($posters_dir, 0755, true);
    $local_name  = md5($poster_path) . '.jpg';
    $local_path  = $posters_dir . DIRECTORY_SEPARATOR . $local_name;
    if (!file_exists($local_path)) move_uploaded_file($_FILES['img']['tmp_name'], $local_path);
    if (file_exists($local_path)) {
        $meta[$filename]['poster_local'] = posters_url_for($ajax_cwd) . $local_name;
        meta_save($meta, $ajax_cwd);
        echo '{"ok":true}';
    } else { echo '{"ok":false}'; }
    exit;
}

// ── TMDB metadata fetch (AJAX, GET) ───────────────────────────────────────────
if ($get_action === 'fetch_meta') {
    ob_start();
    if (!FM_TMDB_API_KEY) { ob_clean(); header('Content-Type: application/json'); echo json_encode(array('error' => 'No API key')); exit; }
    $filename = isset($_GET['file']) ? basename($_GET['file']) : '';
    if (!$filename) { ob_clean(); header('Content-Type: application/json'); echo json_encode(array('error' => 'No file')); exit; }
    $ajax_cwd = current_dir();
    $meta     = meta_load($ajax_cwd);
    // Strip multi-part suffix before TMDB search so "Movie.CD1.mkv" searches
    // for "Movie" rather than "Movie CD1" (which TMDB can't match).
    $_pd_fetch = detect_movie_parts($filename);
    $search_name = ($_pd_fetch !== null)
        ? $_pd_fetch['base'] . '.' . pathinfo($filename, PATHINFO_EXTENSION)
        : $filename;
    $parsed   = parse_movie_name($search_name);
    $result   = tmdb_fetch($parsed['title'], $parsed['year']);
    if ($result) {
        if (!empty($result['poster_path'])) {
            $local = poster_download($result['poster_path'], $ajax_cwd);
            if ($local) $result['poster_local'] = $local;
        }
        $meta[$filename] = $result;
        meta_save($meta, $ajax_cwd);
        ob_clean(); header('Content-Type: application/json');
        echo json_encode(array('ok' => true, 'data' => $result));
    } else {
        $meta[$filename] = array('not_found' => true, 'fetched_at' => time());
        meta_save($meta, $ajax_cwd);
        ob_clean(); header('Content-Type: application/json');
        echo json_encode(array('ok' => false, 'error' => 'Not found on TMDB'));
    }
    exit;
}

// ── Delete meta entry (AJAX, GET) ─────────────────────────────────────────────
if ($get_action === 'delete_meta') {
    header('Content-Type: application/json');
    $ajax_cwd = current_dir();
    $filename = isset($_GET['file']) ? basename($_GET['file']) : '';
    if ($filename) {
        $meta = meta_load($ajax_cwd);
        unset($meta[$filename]);
        meta_save($meta, $ajax_cwd);
    }
    echo json_encode(array('ok' => true)); exit;
}

if (!FM_DEMO_MODE && $_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    $cwd     = current_dir();
    $cwd_rel = relpath($cwd);

    if ($action === 'upload') {
        $allowed  = array_map('trim', explode(',', FM_ALLOWED_EXT));
        $ok = 0; $errs = array();
        $names = isset($_FILES['files']['name']) ? $_FILES['files']['name'] : array();
        foreach ($names as $i => $orig) {
            if ($_FILES['files']['error'][$i] !== UPLOAD_ERR_OK) {
                $errs[] = h($orig) . ': upload error';
                continue;
            }
            $ext = strtolower(pathinfo($orig, PATHINFO_EXTENSION));
            if (!in_array($ext, $allowed, true)) {
                $errs[] = h($orig) . ': extension .' . h($ext) . ' not allowed';
                continue;
            }
            $safe = safe_filename($orig);
            $dest = jail_new(($cwd_rel ? $cwd_rel . '/' : '') . $safe);
            if (!$dest) { $errs[] = h($orig) . ': invalid path'; continue; }
            if (move_uploaded_file($_FILES['files']['tmp_name'][$i], $dest)) $ok++;
            else $errs[] = h($orig) . ': could not save';
        }
        $msg = "$ok file(s) uploaded.";
        if ($errs) $err = implode('<br>', $errs);
    }

    if ($action === 'mkdir') {
        $name = safe_filename(trim(isset($_POST['name']) ? $_POST['name'] : ''));
        if ($name === '') { $err = 'Invalid folder name.'; }
        else {
            $dest = jail_new(($cwd_rel ? $cwd_rel . '/' : '') . $name);
            if (!$dest)             $err = 'Invalid path.';
            elseif (file_exists($dest)) $err = 'Already exists.';
            else { mkdir($dest, 0755); $msg = "Folder '$name' created."; }
        }
    }

    if ($action === 'delete') {
        $target = jail(isset($_POST['target']) ? $_POST['target'] : '');
        if (!$target || $target === FM_ROOT) { $err = 'Invalid target.'; }
        elseif (is_file($target)) { unlink($target); $msg = 'File deleted.'; }
        elseif (is_dir($target)) {
            $items = array_diff(scandir($target), array('.', '..'));
            if (count($items) > 0) $err = 'Folder is not empty.';
            else { rmdir($target); $msg = 'Folder deleted.'; }
        } else $err = 'Not found.';
    }

    if ($action === 'rename') {
        $src      = jail(isset($_POST['source'])   ? $_POST['source']   : '');
        $new_name = safe_filename(trim(isset($_POST['new_name']) ? $_POST['new_name'] : ''));
        if (!$src || $new_name === '') { $err = 'Invalid input.'; }
        else {
            $dest = jail_new(relpath(dirname($src)) . '/' . $new_name);
            if (!$dest)             $err = 'Invalid destination.';
            elseif (file_exists($dest)) $err = 'Name already in use.';
            else { rename($src, $dest); $msg = 'Renamed to ' . h($new_name) . '.'; }
        }
    }
}

// ── Scan directory ─────────────────────────────────────────────────────────────
$cwd     = current_dir();
$cwd_rel = relpath($cwd);
$meta_all = meta_load($cwd);
$ignore      = array('.', '..', basename(__FILE__), '.DS_Store', 'Thumbs.db',
                 '.movies_meta.json', '.posters', '.@__thumb', '.@__qini', '@Transcode', '.deletedByTMM',
                 'listr.css', 'listr-favicon.png', 'index.php_old', 'filemanager.php');
$ignore_ext  = array('php', 'php3', 'php4', 'php5', 'phtml', 'sh', 'bash', 'py', 'pl', 'rb');
$video_ext    = array('mkv','mp4','avi','mov','wmv','flv','mpg','mpeg','m4v','3gp','ts','webm','divx','xvid');
$subtitle_ext = array('srt','sub','ass','ssa','vtt');
$dirs = $files = $subs_by_base = array();
$total_bytes = 0;

if ($dh = opendir($cwd)) {
    while (($e = readdir($dh)) !== false) {
        if (in_array($e, $ignore, true)) continue;
        $ext_check = strtolower(pathinfo($e, PATHINFO_EXTENSION));
        if (in_array($ext_check, $ignore_ext, true)) continue;
        $abs  = $cwd . DIRECTORY_SEPARATOR . $e;
        $stat = @stat($abs);
        $rel  = ($cwd_rel ? $cwd_rel . '/' : '') . $e;
        $item = array(
            'name'  => $e,
            'rel'   => $rel,
            'mtime' => ($stat && isset($stat['mtime'])) ? $stat['mtime'] : 0,
            'bytes' => ($stat && isset($stat['size']))  ? sprintf('%u', $stat['size']) : 0,
            'ext'   => $ext_check,
        );
        if (is_dir($abs)) {
            $dirs[] = $item;
        } elseif (in_array($ext_check, $subtitle_ext, true)) {
            // Index subtitle by lowercase base name for case-insensitive lookup
            $base = strtolower(pathinfo($e, PATHINFO_FILENAME));
            if (!isset($subs_by_base[$base])) $subs_by_base[$base] = array();
            $subs_by_base[$base][] = $item;
        } else {
            $total_bytes += (float)sprintf('%u', $item['bytes']);
            $files[] = $item;
        }
    }
    closedir($dh);
}
usort($dirs,  function($a, $b) { return strcasecmp($a['name'], $b['name']); });
usort($files, function($a, $b) { return $b['mtime'] - $a['mtime']; });

// ── Multi-part movie grouping ─────────────────────────────────────────────────
// Groups e.g. Movie.cd1.mkv + Movie.cd2.mkv onto a single card.
// Secondary parts (part 2+) are stored in $parts_by_base and excluded from the
// main loop via $skip_files; their download links appear on the primary card.
$parts_by_base = array();
foreach ($files as $_pf) {
    if (!in_array($_pf['ext'], $video_ext, true)) continue;
    $_pd = detect_movie_parts($_pf['name']);
    if ($_pd === null) continue;
    $_key = strtolower($_pd['base']);
    if (!isset($parts_by_base[$_key])) $parts_by_base[$_key] = array();
    $parts_by_base[$_key][] = array_merge($_pf, array('part_num' => $_pd['part']));
}
foreach (array_keys($parts_by_base) as $_key) {
    if (count($parts_by_base[$_key]) < 2) { unset($parts_by_base[$_key]); continue; }
    usort($parts_by_base[$_key], function($a, $b) { return $a['part_num'] - $b['part_num']; });
}
$skip_files = array(); // filenames of secondary parts — skipped in main loops
foreach ($parts_by_base as $_group) {
    for ($_i = 1; $_i < count($_group); $_i++) $skip_files[$_group[$_i]['name']] = true;
}

// ── Purge stale metadata entries (file in JSON but no longer on filesystem) ────
if (!empty($meta_all)) {
    $fs_names = array();
    foreach ($files as $f) { $fs_names[$f['name']] = true; }
    $stale = array_diff_key($meta_all, $fs_names);
    if (!empty($stale)) {
        foreach (array_keys($stale) as $k) { unset($meta_all[$k]); }
        meta_save($meta_all, $cwd);
    }
}

$dir_url = $cwd_rel ? '?dir=' . urlencode($cwd_rel) : '?';

// ── Login page ─────────────────────────────────────────────────────────────────
function render_login($err) { ?>
<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login – <?php echo FM_TITLE; ?></title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{display:flex;align-items:center;justify-content:center;min-height:100vh;
     background:#111827;font-family:system-ui,sans-serif}
.card{background:#1f2937;color:#f9fafb;padding:2.5rem;border-radius:12px;
      width:340px;box-shadow:0 20px 60px rgba(0,0,0,.6)}
h1{font-size:1.5rem;margin-bottom:1.75rem;text-align:center}
label{display:block;font-size:.82rem;color:#9ca3af;margin-bottom:.35rem}
input[type=password]{width:100%;padding:.65rem .9rem;background:#111827;
  border:1px solid #374151;border-radius:6px;color:#f9fafb;font-size:1rem;
  margin-bottom:1.2rem;outline:none}
button{width:100%;padding:.75rem;background:#6366f1;border:none;border-radius:6px;
       color:#fff;font-size:1rem;cursor:pointer;font-weight:600}
button:hover{background:#4f46e5}
.err{color:#f87171;font-size:.83rem;margin-bottom:1rem;text-align:center}
</style></head><body>
<div class="card">
  <h1>🗂 <?php echo FM_TITLE; ?></h1>
  <?php if ($err): ?><p class="err"><?php echo h($err); ?></p><?php endif; ?>
  <form method="post">
    <input type="hidden" name="_csrf"  value="<?php echo csrf_token(); ?>">
    <input type="hidden" name="_login" value="1">
    <label for="pw">Password</label>
    <input type="password" id="pw" name="pw" autofocus required autocomplete="current-password">
    <button type="submit">Sign in</button>
  </form>
</div></body></html>
<?php }

// ── Main page ──────────────────────────────────────────────────────────────────
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title><?php echo FM_TITLE; ?> — /<?php echo h($cwd_rel); ?></title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{background:#111827;color:#e5e7eb;font-family:system-ui,-apple-system,sans-serif;font-size:.92rem}
a{color:#818cf8;text-decoration:none}a:hover{text-decoration:underline}
#app{display:flex;flex-direction:column;min-height:100vh}
.btn-logout{background:#374151;color:#e5e7eb;padding:.4rem .6rem;
  border-radius:6px;font-size:1rem;text-decoration:none;flex-shrink:0}
.btn-logout:hover{background:#7f1d1d;color:#fff}
#toolbar input[type=search]{background:#111827;border:1px solid #374151;border-radius:6px;
  padding:.4rem .7rem;color:#e5e7eb;width:180px;outline:none;font-size:.84rem;flex-shrink:0}
#toolbar input[type=search]:focus{border-color:#6366f1}
.home-chip{display:inline-flex;align-items:center;padding:.35rem .6rem;
           background:#1e2533;color:#9ca3af;border-radius:8px;text-decoration:none;
           font-size:1rem;border:1px solid #374151;flex-shrink:0}
.home-chip:hover{background:#312e81;color:#fff;border-color:#6366f1}
#toolbar{padding:.6rem 1.2rem;display:flex;gap:.5rem;
         background:#1a2332;border-bottom:1px solid #374151;align-items:center;
         overflow-x:auto;white-space:nowrap;flex-wrap:nowrap}
#dir-nav{display:flex;gap:.4rem;align-items:center;flex:1;overflow-x:auto;min-width:0}
#dir-nav::-webkit-scrollbar{height:4px}
#dir-nav::-webkit-scrollbar-thumb{background:#374151;border-radius:2px}
.dir-chip{display:inline-flex;align-items:center;gap:.3rem;padding:.35rem .75rem;
          background:#243044;color:#c4b5fd;border-radius:20px;text-decoration:none;
          font-size:.82rem;font-weight:500;border:1px solid #374151;flex-shrink:0}
.dir-chip:hover{background:#312e81;border-color:#6366f1;color:#fff}
.dir-chip.parent{color:#9ca3af;background:#1e2533}
.btn{display:inline-flex;align-items:center;gap:.35rem;padding:.45rem .9rem;
     border:none;border-radius:6px;cursor:pointer;font-size:.84rem;font-weight:500;
     text-decoration:none;white-space:nowrap}
.btn-primary{background:#6366f1;color:#fff}.btn-primary:hover{background:#4f46e5}
.btn-secondary{background:#374151;color:#e5e7eb}.btn-secondary:hover{background:#4b5563}
.btn-danger{background:#991b1b;color:#fca5a5}.btn-danger:hover{background:#7f1d1d}
.btn-sm{padding:.3rem .65rem;font-size:.78rem}
#messages{padding:.55rem 1.2rem}
.msg{padding:.55rem 1rem;border-radius:6px;font-size:.85rem;margin-bottom:.4rem}
.msg-ok{background:#14532d;color:#86efac}
.msg-err{background:#7f1d1d;color:#fca5a5}
#file-table-wrap{padding:0 1.2rem 1.2rem;overflow-x:auto}
table{width:100%;border-collapse:collapse}
thead th{padding:.55rem .75rem;text-align:left;font-size:.78rem;text-transform:uppercase;
         letter-spacing:.05em;color:#6b7280;border-bottom:1px solid #374151;
         cursor:pointer;user-select:none;white-space:nowrap}
thead th:hover{color:#e5e7eb}
tbody tr{border-bottom:1px solid #1f2937}
tbody tr:hover{background:#1e2939}
td{padding:.5rem .75rem;vertical-align:middle}
.col-icon{width:2rem;font-size:1.15rem}
.col-name{word-break:break-all}
.col-size,.col-date{white-space:nowrap;color:#9ca3af;text-align:right;font-size:.83rem}
.col-actions{white-space:nowrap;text-align:right}
.folder-row td.col-name a{color:#fbbf24;font-weight:500}
.row-hidden{display:none!important}
th .si{margin-left:.25rem;opacity:.4}
th.sorted-asc .si::after{content:'↑';opacity:1}
th.sorted-desc .si::after{content:'↓';opacity:1}
.modal-bg{display:none;position:fixed;top:0;left:0;right:0;bottom:0;
          background:rgba(0,0,0,.6);z-index:1000;align-items:center;justify-content:center}
.modal-bg.open{display:flex}
.modal{background:#1f2937;border-radius:12px;padding:1.75rem;width:90%;max-width:520px;
       box-shadow:0 20px 60px rgba(0,0,0,.6);max-height:90vh;display:flex;flex-direction:column}
.modal h2{margin-bottom:1rem;font-size:1.1rem}
.modal-body{flex:1;overflow:auto}
.modal-footer{margin-top:1rem;display:flex;gap:.5rem;justify-content:flex-end}
.fm-label{display:block;font-size:.82rem;color:#9ca3af;margin-bottom:.35rem;margin-top:.75rem}
.fm-label:first-child{margin-top:0}
.fm-input{width:100%;padding:.55rem .8rem;background:#111827;
  border:1px solid #374151;border-radius:6px;color:#e5e7eb;font-size:.9rem}
#drop-zone{border:2px dashed #374151;border-radius:8px;padding:2rem;text-align:center;
           color:#6b7280;cursor:pointer;margin-bottom:1rem}
#drop-zone.drag-over{border-color:#6366f1;color:#a5b4fc}
#drop-zone p{margin:.4rem 0;font-size:.85rem}
#file-list-preview{list-style:none;padding:0;font-size:.82rem;color:#9ca3af;max-height:150px;overflow:auto}
#file-list-preview li{padding:.2rem 0;border-bottom:1px solid #1f2937}
#preview-modal .modal{max-width:900px}
#preview-container{text-align:center}
#preview-container img{max-width:100%;max-height:72vh;border-radius:6px}
#preview-container video,#preview-container audio{max-width:100%}
#preview-container pre{text-align:left;background:#111827;padding:1rem;border-radius:6px;
  overflow:auto;max-height:65vh;font-size:.82rem;color:#d1fae5;white-space:pre-wrap}
#preview-container iframe{width:100%;height:70vh;border:none;border-radius:6px}
.empty{padding:3rem;text-align:center;color:#4b5563}
.empty span{font-size:2.5rem;display:block;margin-bottom:.75rem}
#footer{padding:.6rem 1.2rem;font-size:.78rem;color:#4b5563;
        border-top:1px solid #1f2937;display:flex;justify-content:space-between;flex-wrap:wrap;gap:.5rem}
/* ── Card grid ── */
#card-grid{display:none;padding:1rem 1.2rem;
  grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:1.2rem}
#file-table-wrap.hidden{display:none}
.card{background:#1f2937;border-radius:10px;overflow:hidden;
      display:flex;flex-direction:column;transition:.2s;position:relative}
.card:hover{transform:translateY(-3px);box-shadow:0 8px 24px rgba(0,0,0,.4)}
.card-poster{width:100%;aspect-ratio:2/3;object-fit:cover;display:block;background:#111827}
.card-poster-placeholder{width:100%;aspect-ratio:2/3;background:#111827;
  display:flex;align-items:center;justify-content:center;font-size:3rem}
.card-body{padding:.75rem;flex:1;display:flex;flex-direction:column;gap:.3rem}
.card-title{font-weight:600;font-size:.88rem;line-height:1.3;color:#f9fafb}
.card-year{font-size:.75rem;color:#6b7280}
.card-rating{font-size:.8rem}
.card-overview{font-size:.75rem;color:#9ca3af;line-height:1.4;
               overflow:hidden;display:-webkit-box;-webkit-line-clamp:3;-webkit-box-orient:vertical}
.card-footer{padding:.5rem .75rem;display:flex;gap:.4rem;flex-wrap:wrap;
             border-top:1px solid #374151;margin-top:auto}
.card-btn{font-size:.72rem;padding:.25rem .55rem;border-radius:4px;text-decoration:none;
          background:#374151;color:#e5e7eb;border:none;cursor:pointer;white-space:nowrap}
.card-btn:hover{background:#4b5563;text-decoration:none}
.card-btn.tmdb{background:#01b4e4;color:#fff}.card-btn.tmdb:hover{background:#0099c7}
.card-btn.allocine{background:#feb800;color:#000}.card-btn.allocine:hover{background:#d9a000}
.card-btn-watch{background:#374151;color:#9ca3af}
.card-btn-watch.active{background:#166534!important;color:#86efac!important}
.card-btn-watch.active:hover{background:#15803d!important}
.card.watched{opacity:.55;transition:.2s}
.card.watched:hover{opacity:.85}
.card-watched-badge{display:none;position:absolute;top:6px;left:6px;background:rgba(22,101,52,.9);
  color:#86efac;font-size:.7rem;padding:2px 6px;border-radius:4px;pointer-events:none;z-index:2}
.card.watched .card-watched-badge{display:block}
#ftable tr.row-watched td{opacity:.4}
#ftable tr.row-watched .btn-watch-row,.btn-watch-row.active{background:#166534!important;color:#86efac!important}
.card-fetching{position:absolute;top:.4rem;right:.4rem;font-size:.7rem;
               background:#6366f1;color:#fff;padding:.15rem .4rem;border-radius:4px}
.card-not-found{position:absolute;top:.4rem;right:.4rem;font-size:.7rem;
                background:#374151;color:#9ca3af;padding:.15rem .4rem;border-radius:4px}
/* Stars */
.stars{position:relative;display:inline-block;font-size:.9rem;line-height:1}
.stars-bg{color:#374151}
.stars-fill{position:absolute;top:0;left:0;overflow:hidden;white-space:nowrap;color:#fbbf24}
.rating-num{font-size:.78rem;color:#9ca3af;margin-left:.2rem}
.no-rating{color:#4b5563;font-size:.78rem}
/* Sync progress */
#sync-bar{display:none;padding:.4rem 1.2rem;background:#1e1b4b;font-size:.82rem;color:#a5b4fc;
          border-bottom:1px solid #374151}
#sync-bar.active{display:block}
.card-btn.card-btn-sub{background:#065f46;color:#6ee7b7}.card-btn.card-btn-sub:hover{background:#047857}
.btn-active{background:#4f46e5!important}
/* ── Mobile ── */
@media(max-width:600px){
  #toolbar{padding:.4rem .6rem;gap:.3rem}
  .home-chip{padding:.3rem .5rem;font-size:.9rem}
  .dir-chip{padding:.25rem .55rem;font-size:.75rem}
  #btn-list,#btn-grid{padding:.35rem .55rem;font-size:.85rem}
  #btn-sync{padding:.35rem .55rem;font-size:.8rem}
  #toolbar input[type=search]{width:100px;padding:.3rem .5rem;font-size:.78rem}
  .btn-logout{padding:.3rem .5rem;font-size:.85rem}
  #toolbar span[style]{display:none}
  /* 3 colonnes, max 4 lignes visibles puis scroll */
  #card-grid{grid-template-columns:repeat(3,1fr)!important;gap:.3rem;padding:.3rem}
  .card-poster,.card-poster-placeholder{aspect-ratio:2/3}
  .card-body{padding:.25rem .3rem;gap:.15rem}
  .card-title{font-size:.68rem;-webkit-line-clamp:2}
  .card-year{font-size:.6rem}
  .card-overview{display:none}
  .card-rating{font-size:.62rem}
  .card-footer{padding:.2rem .3rem;gap:.15rem;flex-wrap:wrap}
  .card-btn{padding:.15rem .28rem;font-size:.6rem}
  .card-btn-watch{font-size:.9rem;padding:.3rem .5rem;min-height:32px;min-width:32px}
  .col-date,.col-size{display:none}
  td{padding:.4rem .5rem}
}
@media(min-width:601px) and (max-width:900px){
  #card-grid{grid-template-columns:repeat(3,1fr)!important}
}
/* ── Movie info modal ── */
#movie-modal .modal{max-width:720px;padding:0;overflow:hidden}
#movie-modal-inner{display:flex;min-height:300px}
#movie-modal-poster{flex-shrink:0;width:220px;background:#111827;overflow:hidden}
#movie-modal-poster img{width:100%;height:100%;object-fit:cover;display:block}
#movie-modal-poster-ph{width:100%;min-height:330px;display:flex;align-items:center;justify-content:center;font-size:4rem;background:#111827}
#movie-modal-info{padding:1.4rem 1.6rem;flex:1;overflow-y:auto;max-height:80vh;display:flex;flex-direction:column;gap:.6rem}
#movie-modal-title{font-size:1.2rem;font-weight:700;color:#f9fafb;line-height:1.3}
#movie-modal-meta{font-size:.8rem;color:#6b7280}
#movie-modal-overview{font-size:.85rem;color:#d1d5db;line-height:1.6;flex:1;white-space:pre-wrap}
#movie-modal-links{display:flex;gap:.5rem;flex-wrap:wrap;padding-top:.75rem;border-top:1px solid #374151;margin-top:auto}
#movie-modal-close{padding:.65rem 1rem;border-top:1px solid #374151;display:flex;justify-content:flex-end}
.card{cursor:context-menu}
@media(max-width:600px){
  #movie-modal-inner{flex-direction:column}
  #movie-modal-poster{width:100%;max-height:240px}
  #movie-modal-poster img{height:240px;object-fit:cover}
  #movie-modal-info{max-height:55vh;padding:1rem}
}
</style>
</head>
<body>
<div id="app">

<div id="toolbar">
  <a class="home-chip" href="?" title="Accueil">🏠</a>
  <div id="dir-nav">
    <?php if ($cwd_rel !== ''): ?>
    <?php
      $parent_rel = dirname($cwd_rel);
      $parent_url = ($parent_rel === '.' || $parent_rel === '') ? '?' : '?dir=' . urlencode($parent_rel);
    ?>
    <a class="dir-chip parent" href="<?php echo $parent_url; ?>">← ..</a>
    <?php endif; ?>
    <?php foreach ($dirs as $item): ?>
    <a class="dir-chip" href="?dir=<?php echo urlencode($item['rel']); ?>">📁 <?php echo h($item['name']); ?></a>
    <?php endforeach; ?>
    <?php if (empty($dirs)): ?>
    <span style="color:#4b5563;font-size:.82rem;font-style:italic">Aucun sous-dossier</span>
    <?php endif; ?>
  </div>
  <?php if (FM_TMDB_API_KEY): ?>
  <button class="btn btn-secondary" id="btn-sync" onclick="startSync()">🎬 Sync</button>
  <?php endif; ?>
  <button class="btn btn-secondary" id="btn-list" onclick="setView('list')" title="Vue liste">☰</button>
  <button class="btn btn-secondary" id="btn-grid" onclick="setView('grid')" title="Vue grille">⊞</button>
  <span style="color:#6b7280;font-size:.82rem;flex-shrink:0">
    <?php echo count($files); ?> film<?php echo count($files) != 1 ? 's' : ''; ?>
    <?php echo count($files) ? ' — ' . fmt_size($total_bytes) : ''; ?>
  </span>
  <input type="search" id="search" placeholder="Rechercher…" oninput="filterRows(this.value)" autocomplete="off">
  <a class="btn-logout" href="?logout=1" title="Se déconnecter">⏻</a>
</div>

<div id="sync-bar">⏳ Synchronisation en cours… <span id="sync-progress"></span></div>

<?php if ($msg || $err): ?>
<div id="messages">
  <?php if ($msg): ?><div class="msg msg-ok">✓ <?php echo h($msg); ?></div><?php endif; ?>
  <?php if ($err): ?><div class="msg msg-err">✗ <?php echo $err; ?></div><?php endif; ?>
</div>
<?php endif; ?>


<!-- ── Card grid (sibling of file-table-wrap, not inside) ── -->
<div id="card-grid">
<?php if (!empty($files)): ?>
<?php foreach ($files as $item):
  $m      = isset($meta_all[$item['name']]) ? $meta_all[$item['name']] : null;
  $is_vid = in_array($item['ext'], $video_ext, true);
  if (!$is_vid) continue;
  if (isset($skip_files[$item['name']])) continue; // secondary part — shown on primary card
  // Multi-part: collect all parts for this film (sorted by part number)
  $_pd_card   = detect_movie_parts($item['name']);
  $film_parts = ($_pd_card !== null && isset($parts_by_base[strtolower($_pd_card['base'])]))
              ? $parts_by_base[strtolower($_pd_card['base'])]
              : array();
  // Total file size (sum of all parts, or just this file)
  $film_bytes = $item['bytes'];
  if (!empty($film_parts)) {
      $film_bytes = 0;
      foreach ($film_parts as $_fp) $film_bytes += (float)$_fp['bytes'];
  }
  $poster = '';
  if ($m && !empty($m['poster_local'])) {
      $poster = $m['poster_local'];          // fichier local en priorité
  } elseif ($m && !empty($m['poster_path'])) {
      $poster = 'https://image.tmdb.org/t/p/w300' . $m['poster_path']; // fallback CDN
  }
  $tmdb_url    = ($m && !empty($m['tmdb_id']))
               ? 'https://www.themoviedb.org/movie/' . $m['tmdb_id']
               : '';
  $alloc_title = ($m && !empty($m['title'])) ? $m['title'] : pathinfo($item['name'], PATHINFO_FILENAME);
  $alloc_url   = 'https://www.allocine.fr/rechercher/movie/?q=' . urlencode($alloc_title);
  $subs = isset($subs_by_base[strtolower(pathinfo($item['name'], PATHINFO_FILENAME))]) ? $subs_by_base[strtolower(pathinfo($item['name'], PATHINFO_FILENAME))] : array();
  $card_meta = json_encode(array(
    'title'        => $m && !empty($m['title'])       ? $m['title']       : pathinfo($item['name'], PATHINFO_FILENAME),
    'year'         => $m && !empty($m['year'])         ? (int)$m['year']   : null,
    'rating'       => $m && isset($m['rating'])        ? $m['rating']      : null,
    'overview'     => $m && !empty($m['overview'])     ? $m['overview']    : '',
    'poster_path'  => $m && !empty($m['poster_path'])  ? $m['poster_path'] : '',
    'poster_local' => $m && !empty($m['poster_local']) ? $m['poster_local']: '',
    'tmdb_url'     => $tmdb_url,
    'alloc_url'    => $alloc_url,
    'filename'     => $item['name'],
    'filesize'     => fmt_size($film_bytes),
    'parts'        => count($film_parts) > 0 ? count($film_parts) : 1,
  ));
?>
<div class="card" data-name="<?php echo h($item['name']); ?>" id="card-<?php echo md5($item['name']); ?>" data-meta="<?php echo h($card_meta); ?>">
  <span class="card-watched-badge">✓ Vu</span>
  <?php if ($poster): ?>
    <img class="card-poster" src="<?php echo h($poster); ?>" alt=""<?php if (empty($m['poster_local']) && !empty($m['poster_path'])): ?> crossorigin="anonymous" data-cache-name="<?php echo h($item['name']); ?>"<?php endif; ?>>
  <?php else: ?>
    <div class="card-poster-placeholder">🎬</div>
  <?php endif; ?>
  <?php if ($not_found): ?>
    <span class="card-not-found" title="Non trouvé sur TMDB">?</span>
  <?php endif; ?>
  <div class="card-body">
    <div class="card-title"><?php echo $m && !empty($m['title']) ? h($m['title']) : h(pathinfo($item['name'], PATHINFO_FILENAME)); ?></div>
    <?php if ($m && !empty($m['year'])): ?>
    <div class="card-year"><?php echo (int)$m['year']; ?> — <?php echo fmt_size($film_bytes); ?><?php if (!empty($film_parts)): ?> — <?php echo count($film_parts); ?> parties<?php endif; ?></div>
    <?php else: ?>
    <div class="card-year"><?php echo fmt_size($film_bytes); ?><?php if (!empty($film_parts)): ?> — <?php echo count($film_parts); ?> parties<?php endif; ?></div>
    <?php endif; ?>
    <?php if ($m && isset($m['rating'])): ?>
    <div class="card-rating"><?php echo star_html($m['rating']); ?></div>
    <?php endif; ?>
    <?php if ($m && !empty($m['overview'])): ?>
    <div class="card-overview"><?php echo h($m['overview']); ?></div>
    <?php endif; ?>
  </div>
  <div class="card-footer">
    <?php if (empty($film_parts)): ?>
    <a class="card-btn" href="?action=download&amp;file=<?php echo urlencode($item['rel']); ?>" onclick="markWatched(<?php echo h(json_encode($item['name'])); ?>)">⬇ Film</a>
    <?php else: ?>
    <?php foreach ($film_parts as $_pi => $_part): ?>
    <a class="card-btn" href="?action=download&amp;file=<?php echo urlencode($_part['rel']); ?>" onclick="markWatched(<?php echo h(json_encode($item['name'])); ?>)" title="<?php echo h($_part['name']); ?>">⬇ Partie <?php echo ($_pi + 1); ?></a>
    <?php endforeach; ?>
    <?php endif; ?>
    <?php foreach ($subs as $sub): ?>
    <a class="card-btn card-btn-sub" href="?action=download&amp;file=<?php echo urlencode($sub['rel']); ?>" title="<?php echo h($sub['name']); ?>">💬 <?php echo strtoupper($sub['ext']); ?></a>
    <?php endforeach; ?>
    <?php if ($tmdb_url): ?>
    <a class="card-btn tmdb" href="<?php echo h($tmdb_url); ?>" target="_blank">TMDB</a>
    <?php endif; ?>
    <a class="card-btn allocine" href="<?php echo h($alloc_url); ?>" target="_blank">Allociné</a>
    <button class="card-btn card-btn-watch" onclick="toggleWatched(this,<?php echo h(json_encode($item['name'])); ?>)" title="Marquer comme vu">👁</button>
    <?php if (FM_TMDB_API_KEY): ?>
    <button class="card-btn card-btn-refresh" onclick="syncOne(this,<?php echo h(json_encode($item['name'])); ?>)" title="Re-chercher sur TMDB">↺</button>
    <?php endif; ?>
  </div>
</div>
<?php endforeach; ?>
<?php endif; ?>
</div>

<div id="file-table-wrap">
<?php if (empty($dirs) && empty($files)): ?>
  <div class="empty"><span>🌑</span>This folder is empty.</div>
<?php else: ?>

<table id="ftable">
<thead>
  <tr>
    <th class="col-icon"></th>
    <th class="col-name"    onclick="sortTable(this,1)">Nom <span class="si"></span></th>
    <th class="col-size"    onclick="sortTable(this,2)">Taille <span class="si"></span></th>
    <th class="col-date"    onclick="sortTable(this,3)">Date <span class="si"></span></th>
    <th class="col-actions">Actions</th>
  </tr>
</thead>
<tbody id="tbody">

<?php foreach ($files as $item):
  if (isset($skip_files[$item['name']])) continue; // secondary part — shown on primary row
  $ptype = previewable($item['ext']);
  $m     = isset($meta_all[$item['name']]) ? $meta_all[$item['name']] : null;
  $subs  = isset($subs_by_base[strtolower(pathinfo($item['name'], PATHINFO_FILENAME))]) ? $subs_by_base[strtolower(pathinfo($item['name'], PATHINFO_FILENAME))] : array();
  // Multi-part lookup for table rows
  $_pd_row    = detect_movie_parts($item['name']);
  $row_parts  = ($_pd_row !== null && isset($parts_by_base[strtolower($_pd_row['base'])]))
              ? $parts_by_base[strtolower($_pd_row['base'])]
              : array();
  $row_bytes  = $item['bytes'];
  if (!empty($row_parts)) {
      $row_bytes = 0;
      foreach ($row_parts as $_rp) $row_bytes += (float)$_rp['bytes'];
  }
?>
<tr data-name="<?php echo h($item['name']); ?>">
  <td class="col-icon"><?php echo file_icon($item['ext']); ?></td>
  <td class="col-name" data-val="<?php echo h($item['name']); ?>">
    <?php if ($ptype): ?>
      <a href="#" onclick="openPreview(<?php echo json_encode($item['rel']); ?>,<?php echo json_encode($item['name']); ?>,<?php echo json_encode($ptype); ?>);return false"><?php echo h($item['name']); ?></a>
    <?php else: ?>
      <a href="?action=download&amp;file=<?php echo urlencode($item['rel']); ?>"><?php echo h($item['name']); ?></a>
    <?php endif; ?>
    <?php if ($m && !empty($m['title'])): ?>
      <br><small style="color:#9ca3af"><?php echo h($m['title']); ?>
      <?php if (!empty($m['year'])): ?>(<?php echo (int)$m['year']; ?>)<?php endif; ?>
      <?php if (isset($m['rating'])): ?>— <?php echo $m['rating']; ?>/10<?php endif; ?>
      </small>
    <?php endif; ?>
  </td>
  <td class="col-size" data-val="<?php echo $row_bytes; ?>"><?php echo fmt_size($row_bytes); ?><?php if (!empty($row_parts)): ?> <small style="color:#6b7280">(<?php echo count($row_parts); ?>×)</small><?php endif; ?></td>
  <td class="col-date" data-val="<?php echo $item['mtime']; ?>"><?php echo date('Y-m-d H:i', $item['mtime']); ?></td>
  <td class="col-actions">
    <?php if (empty($row_parts)): ?>
    <a class="btn btn-secondary btn-sm" href="?action=download&amp;file=<?php echo urlencode($item['rel']); ?>" onclick="markWatched(<?php echo h(json_encode($item['name'])); ?>)" title="⬇ Film">⬇</a>
    <?php else: ?>
    <?php foreach ($row_parts as $_pi => $_part): ?>
    <a class="btn btn-secondary btn-sm" href="?action=download&amp;file=<?php echo urlencode($_part['rel']); ?>" onclick="markWatched(<?php echo h(json_encode($item['name'])); ?>)" title="<?php echo h($_part['name']); ?>">⬇<?php echo ($_pi + 1); ?></a>
    <?php endforeach; ?>
    <?php endif; ?>
    <?php foreach ($subs as $sub): ?>
    <a class="btn btn-secondary btn-sm" href="?action=download&amp;file=<?php echo urlencode($sub['rel']); ?>" title="<?php echo h($sub['name']); ?>">💬</a>
    <?php endforeach; ?>
    <?php if ($ptype): ?>
    <button class="btn btn-secondary btn-sm"
      onclick="openPreview(<?php echo h(json_encode($item['rel'])); ?>,<?php echo h(json_encode($item['name'])); ?>,<?php echo h(json_encode($ptype)); ?>)">▶</button>
    <?php endif; ?>
    <button class="btn btn-secondary btn-sm btn-watch-row" onclick="toggleWatched(this,<?php echo h(json_encode($item['name'])); ?>)" title="Marquer comme vu">👁</button>
  </td>
</tr>
<?php endforeach; ?>

</tbody>
</table>
<?php endif; ?>
</div>

<div id="footer">
  <span>SecureFileManager<?php echo FM_DEMO_MODE ? ' — <em>Read-only mode</em>' : ''; ?></span>
  <span><?php echo h($cwd_rel ? $cwd_rel : '/'); ?></span>
</div>
</div>

<!-- Upload modal -->
<div class="modal-bg" id="upload-modal">
<div class="modal">
  <h2>⬆ Upload files</h2>
  <form method="post" enctype="multipart/form-data" action="<?php echo $dir_url; ?>">
    <input type="hidden" name="_csrf"  value="<?php echo csrf_token(); ?>">
    <input type="hidden" name="action" value="upload">
    <div id="drop-zone" onclick="document.getElementById('file-input').click()">
      <p style="font-size:2rem">📂</p>
      <p>Drop files here or <strong style="color:#818cf8">click to browse</strong></p>
      <p>Max <?php echo FM_MAX_UPLOAD_MB; ?> MB per file &mdash; allowed: <?php echo FM_ALLOWED_EXT; ?></p>
    </div>
    <input type="file" id="file-input" name="files[]" multiple style="display:none">
    <ul id="file-list-preview"></ul>
    <div class="modal-footer">
      <button type="button" class="btn btn-secondary" onclick="closeModal('upload-modal')">Cancel</button>
      <button type="submit" class="btn btn-primary">Upload</button>
    </div>
  </form>
</div>
</div>

<!-- New folder modal -->
<div class="modal-bg" id="mkdir-modal">
<div class="modal">
  <h2>📁 New folder</h2>
  <form method="post" action="<?php echo $dir_url; ?>">
    <input type="hidden" name="_csrf"  value="<?php echo csrf_token(); ?>">
    <input type="hidden" name="action" value="mkdir">
    <label class="fm-label" for="mkdir-name">Folder name</label>
    <input class="fm-input" type="text" id="mkdir-name" name="name" required autofocus>
    <div class="modal-footer">
      <button type="button" class="btn btn-secondary" onclick="closeModal('mkdir-modal')">Cancel</button>
      <button type="submit" class="btn btn-primary">Create</button>
    </div>
  </form>
</div>
</div>

<!-- Rename modal -->
<div class="modal-bg" id="rename-modal">
<div class="modal">
  <h2>✏ Rename</h2>
  <form method="post" action="<?php echo $dir_url; ?>">
    <input type="hidden" name="_csrf"    value="<?php echo csrf_token(); ?>">
    <input type="hidden" name="action"   value="rename">
    <input type="hidden" name="source"   id="rename-source">
    <label class="fm-label" for="rename-name">New name</label>
    <input class="fm-input" type="text" id="rename-name" name="new_name" required>
    <div class="modal-footer">
      <button type="button" class="btn btn-secondary" onclick="closeModal('rename-modal')">Cancel</button>
      <button type="submit" class="btn btn-primary">Rename</button>
    </div>
  </form>
</div>
</div>

<!-- Delete modal -->
<div class="modal-bg" id="delete-modal">
<div class="modal">
  <h2>🗑 Confirm delete</h2>
  <p id="delete-msg" style="color:#fca5a5;margin-bottom:.5rem"></p>
  <p style="font-size:.82rem;color:#9ca3af">This action cannot be undone.</p>
  <form method="post" action="<?php echo $dir_url; ?>">
    <input type="hidden" name="_csrf"   value="<?php echo csrf_token(); ?>">
    <input type="hidden" name="action"  value="delete">
    <input type="hidden" name="target"  id="delete-target">
    <div class="modal-footer">
      <button type="button" class="btn btn-secondary" onclick="closeModal('delete-modal')">Cancel</button>
      <button type="submit" class="btn btn-danger">Delete</button>
    </div>
  </form>
</div>
</div>

<!-- Movie info modal -->
<div class="modal-bg" id="movie-modal" onclick="if(event.target===this)closeModal('movie-modal')">
<div class="modal">
  <div id="movie-modal-inner">
    <div id="movie-modal-poster">
      <img id="movie-modal-poster-img" src="" alt="" style="display:none">
      <div id="movie-modal-poster-ph" style="display:none">🎬</div>
    </div>
    <div id="movie-modal-info">
      <div id="movie-modal-title"></div>
      <div id="movie-modal-meta"></div>
      <div id="movie-modal-rating"></div>
      <div id="movie-modal-overview"></div>
      <div id="movie-modal-links"></div>
    </div>
  </div>
  <div id="movie-modal-close">
    <button class="btn btn-secondary" onclick="closeModal('movie-modal')">Fermer</button>
  </div>
</div>
</div>

<!-- Preview modal -->
<div class="modal-bg" id="preview-modal" onclick="if(event.target===this)closeModal('preview-modal')">
<div class="modal">
  <h2 id="preview-title" style="word-break:break-all"></h2>
  <div class="modal-body" id="preview-container"></div>
  <div class="modal-footer">
    <a id="preview-dl" class="btn btn-secondary" href="#">⬇ Download</a>
    <button class="btn btn-secondary" onclick="closeModal('preview-modal')">Close</button>
  </div>
</div>
</div>

<script>
function openModal(id) {
  document.getElementById(id).className += ' open';
  var f = document.querySelector('#'+id+' input:not([type=hidden])');
  if (f) setTimeout(function(){ f.focus(); }, 50);
}
function closeModal(id) {
  document.getElementById(id).className = document.getElementById(id).className.replace(' open','');
  if (id === 'preview-modal') document.getElementById('preview-container').innerHTML = '';
}
document.addEventListener('keydown', function(e) {
  if (e.key === 'Escape') {
    var modals = document.querySelectorAll('.modal-bg.open');
    for (var i = 0; i < modals.length; i++) modals[i].className = modals[i].className.replace(' open','');
  }
});

function openRename(rel, name) {
  document.getElementById('rename-source').value = rel;
  document.getElementById('rename-name').value   = name;
  openModal('rename-modal');
}
function openDelete(rel, name) {
  document.getElementById('delete-target').value = rel;
  document.getElementById('delete-msg').textContent = 'Delete "' + name + '"?';
  openModal('delete-modal');
}

var dropZone  = document.getElementById('drop-zone');
var fileInput = document.getElementById('file-input');
var preview   = document.getElementById('file-list-preview');

function updatePreview(files) {
  preview.innerHTML = '';
  for (var i = 0; i < files.length; i++) {
    var li = document.createElement('li');
    var sz = files[i].size > 1048576 ? Math.round(files[i].size/1048576)+'MB' : Math.round(files[i].size/1024)+'KB';
    li.textContent = files[i].name + ' (' + sz + ')';
    preview.appendChild(li);
  }
}
fileInput.addEventListener('change', function() { updatePreview(fileInput.files); });
dropZone.addEventListener('dragover',  function(e) { e.preventDefault(); dropZone.className += ' drag-over'; });
dropZone.addEventListener('dragleave', function()  { dropZone.className = dropZone.className.replace(' drag-over',''); });
dropZone.addEventListener('drop', function(e) {
  e.preventDefault();
  dropZone.className = dropZone.className.replace(' drag-over','');
  if (e.dataTransfer.files.length) { fileInput.files = e.dataTransfer.files; updatePreview(e.dataTransfer.files); }
});

function openPreview(rel, name, type) {
  document.getElementById('preview-title').textContent = name;
  document.getElementById('preview-dl').href = '?action=download&file=' + encodeURIComponent(rel);
  var url = '?action=preview&file=' + encodeURIComponent(rel);
  var html = '';
  if (type === 'image')      html = '<img src="'+url+'" alt="">';
  else if (type === 'video') html = '<video controls autoplay style="max-width:100%;max-height:72vh"><source src="'+url+'"></video>';
  else if (type === 'audio') html = '<audio controls autoplay style="width:100%"><source src="'+url+'"></audio>';
  else if (type === 'pdf')   html = '<iframe src="'+url+'"></iframe>';
  else if (type === 'text') {
    fetch(url).then(function(r){ return r.text(); }).then(function(t){
      document.getElementById('preview-container').innerHTML = '<pre>'+t.replace(/&/g,'&amp;').replace(/</g,'&lt;')+'</pre>';
    });
    html = '<p style="color:#6b7280;padding:1rem">Loading…</p>';
  }
  document.getElementById('preview-container').innerHTML = html;
  openModal('preview-modal');
}

function filterRows(q) {
  q = q.toLowerCase();
  var rows = document.querySelectorAll('#tbody tr[data-name]');
  for (var i = 0; i < rows.length; i++) {
    var match = q === '' || rows[i].getAttribute('data-name').toLowerCase().indexOf(q) !== -1;
    rows[i].className = match ? rows[i].className.replace(' row-hidden','') : rows[i].className + ' row-hidden';
  }
  var cards = document.querySelectorAll('#card-grid .card');
  for (var j = 0; j < cards.length; j++) {
    var cm = q === '' || cards[j].getAttribute('data-name').toLowerCase().indexOf(q) !== -1;
    cards[j].style.display = cm ? '' : 'none';
  }
}

// ── View toggle ──
var currentView = 'grid';
try { currentView = localStorage.getItem('fm_view') || 'grid'; } catch(e) {}
function setView(v) {
  currentView = v;
  try { localStorage.setItem('fm_view', v); } catch(e) {}
  var grid  = document.getElementById('card-grid');
  var table = document.getElementById('file-table-wrap');
  var btnL  = document.getElementById('btn-list');
  var btnG  = document.getElementById('btn-grid');
  if (!grid || !table) return;
  if (v === 'grid') {
    grid.style.display  = 'grid';
    table.style.display = 'none';
    if (btnG) btnG.style.background = '#4f46e5';
    if (btnL) btnL.style.background = '';
  } else {
    grid.style.display  = 'none';
    table.style.display = '';
    if (btnL) btnL.style.background = '#4f46e5';
    if (btnG) btnG.style.background = '';
  }
}
setView(currentView);

// ── TMDB sync ──
var currentDir = <?php echo json_encode($cwd_rel); ?>;
function fetchOne(filename) {
  var dirParam = currentDir ? '&dir=' + encodeURIComponent(currentDir) : '';
  return fetch('?action=fetch_meta&file=' + encodeURIComponent(filename) + dirParam)
    .then(function(r){ return r.json(); })
    .then(function(data) {
      if (data.ok && data.data) {
        var escaped = filename.replace(/\\/g,'\\\\').replace(/"/g,'\\"');
        var card = document.querySelector('#card-grid .card[data-name="' + escaped + '"]');
        if (card) refreshCard(card, filename, data.data);
      }
      return data;
    });
}

function syncOne(btn, filename) {
  btn.disabled = true;
  btn.textContent = '⏳';
  fetchOne(filename).then(function(data) {
    btn.textContent = data.ok ? '✓' : '✗';
    btn.title = data.ok ? 'Synchronisé !' : ('Non trouvé : ' + (data.error || ''));
    setTimeout(function(){ btn.textContent = '↺'; btn.disabled = false; btn.title = 'Re-chercher sur TMDB'; }, 3000);
  }).catch(function(e) {
    btn.textContent = '✗';
    btn.title = 'Erreur : ' + e;
    setTimeout(function(){ btn.textContent = '↺'; btn.disabled = false; btn.title = 'Re-chercher sur TMDB'; }, 3000);
  });
}

function refreshCard(card, filename, d) {
  // Update poster — prefer local path returned by server
  var posterSrc = d.poster_local ? d.poster_local
                : (d.poster_path ? 'https://image.tmdb.org/t/p/w300' + d.poster_path : '');
  if (posterSrc) {
    var oldImg = card.querySelector('.card-poster, .card-poster-placeholder');
    var newImg = document.createElement('img');
    newImg.className = 'card-poster';
    newImg.src = posterSrc;
    newImg.alt = '';
    newImg.setAttribute('loading', 'lazy');
    if (oldImg) oldImg.parentNode.replaceChild(newImg, oldImg);
  }
  // Update body
  var body = card.querySelector('.card-body');
  if (body) {
    var sizeText = '';
    var yr = body.querySelector('.card-year');
    if (yr) { var parts = yr.textContent.split('—'); sizeText = parts.length > 1 ? parts[1].trim() : ''; }
    var stars = d.rating ? '<div class="card-rating">' + renderStars(d.rating) + '</div>' : '';
    var ov    = d.overview ? '<div class="card-overview">' + escH(d.overview) + '</div>' : '';
    body.innerHTML = '<div class="card-title">' + escH(d.title || filename) + '</div>'
                   + '<div class="card-year">' + (d.year || '') + (sizeText ? ' — ' + sizeText : '') + '</div>'
                   + stars + ov;
  }
  // Remove "not found" badge if present
  var nf = card.querySelector('.card-not-found');
  if (nf) nf.parentNode.removeChild(nf);
}

function renderStars(rating) {
  var pct = Math.round((rating/10)*100);
  return '<span class="stars" title="'+rating+'/10">'
       + '<span class="stars-fill" style="width:'+pct+'%">★★★★★</span>'
       + '<span class="stars-bg">★★★★★</span>'
       + '</span> <span class="rating-num">'+rating+'</span>';
}
function escH(s) { var d=document.createElement('div'); d.textContent=s; return d.innerHTML; }

// Simple MD5 is complex — use a hash based on charCode sum for card IDs instead
function md5hex(s) {
  var h = 0;
  for (var i = 0; i < s.length; i++) h = (Math.imul(31, h) + s.charCodeAt(i)) | 0;
  return (h >>> 0).toString(16).padStart(8,'0');
}

var syncQueue = [], syncTotal = 0, syncDone = 0;
function startSync() {
  var cards = document.querySelectorAll('#card-grid .card');
  syncQueue = [];
  for (var i = 0; i < cards.length; i++) {
    var name = cards[i].getAttribute('data-name');
    var nf   = cards[i].querySelector('.card-not-found');
    var hasPoster = cards[i].querySelector('.card-poster');
    if (!hasPoster) syncQueue.push(name);
  }
  if (!syncQueue.length) { alert('Toutes les métadonnées sont déjà chargées.'); return; }
  syncTotal = syncQueue.length;
  syncDone  = 0;
  document.getElementById('sync-bar').className = 'active';
  document.getElementById('btn-sync').disabled = true;
  syncNext();
}
function syncNext() {
  if (!syncQueue.length) {
    document.getElementById('sync-bar').className = '';
    document.getElementById('btn-sync').disabled = false;
    document.getElementById('sync-progress').textContent = '';
    return;
  }
  var filename = syncQueue.shift();
  syncDone++;
  document.getElementById('sync-progress').textContent =
    syncDone + '/' + syncTotal + ' — ' + filename;
  fetchOne(filename).then(function(){ setTimeout(syncNext, 300); }).catch(function(e) {
    console.warn('Sync error for ' + filename + ':', e);
    setTimeout(syncNext, 300);
  });
}

function sortTable(th, colIdx) {
  var tbody = document.getElementById('tbody');
  var rows  = Array.prototype.slice.call(tbody.querySelectorAll('tr[data-name]'));
  var ths   = document.querySelectorAll('#ftable thead th');
  for (var i = 0; i < ths.length; i++) ths[i].className = ths[i].className.replace(' sorted-asc','').replace(' sorted-desc','');
  sortDir = (sortCol === colIdx) ? sortDir * -1 : 1;
  sortCol = colIdx;
  th.className += sortDir === 1 ? ' sorted-asc' : ' sorted-desc';
  rows.sort(function(a, b) {
    var av = (a.cells[colIdx] && a.cells[colIdx].getAttribute('data-val')) || '';
    var bv = (b.cells[colIdx] && b.cells[colIdx].getAttribute('data-val')) || '';
    var num = !isNaN(av) && !isNaN(bv);
    return sortDir * (num ? av - bv : av.localeCompare(bv, undefined, {sensitivity:'base'}));
  });
  var folderRows = Array.prototype.slice.call(tbody.querySelectorAll('tr.folder-row'));
  var fileRows   = rows.filter(function(r){ return !r.classList.contains('folder-row'); });
  var sortedFolders = rows.filter(function(r){ return r.getAttribute('data-name') !== null && r.classList.contains('folder-row'); });
  var parentRow = folderRows.filter(function(r){ return !r.getAttribute('data-name'); });
  parentRow.concat(sortedFolders).concat(fileRows).forEach(function(r){ tbody.appendChild(r); });
}

var msgs = document.querySelectorAll('.msg');
for (var i = 0; i < msgs.length; i++) {
  (function(m){ setTimeout(function(){ m.style.opacity='0'; m.style.transition='opacity 1s'; }, 5000); })(msgs[i]);
}

// ── Watched list (localStorage) ────────────────────────────────────────────────
function getWatched() {
  try { return JSON.parse(localStorage.getItem('cinenas_watched') || '{}'); } catch(e) { return {}; }
}
function setWatched(w) {
  try { localStorage.setItem('cinenas_watched', JSON.stringify(w)); } catch(e) {}
}
function _esc(s) { return s.replace(/\\/g,'\\\\').replace(/"/g,'\\"'); }
function _setCardWatched(card, on) {
  if (!card) return;
  if (on) { card.classList.add('watched'); }
  else    { card.classList.remove('watched'); }
  var btn = card.querySelector('.card-btn-watch');
  if (btn) {
    if (on) btn.classList.add('active'); else btn.classList.remove('active');
    btn.title = on ? 'Retirer des vus' : 'Marquer comme vu';
  }
}
function _setRowWatched(row, on) {
  if (!row) return;
  if (on) { row.classList.add('row-watched'); }
  else    { row.classList.remove('row-watched'); }
  var btn = row.querySelector('.btn-watch-row');
  if (btn) {
    if (on) btn.classList.add('active'); else btn.classList.remove('active');
    btn.title = on ? 'Retirer des vus' : 'Marquer comme vu';
  }
}
function toggleWatched(btn, filename) {
  var w = getWatched();
  var on = !w[filename];
  if (on) w[filename] = 1; else delete w[filename];
  setWatched(w);
  // Use closest() for reliability on mobile — avoids CSS attribute selector encoding issues
  var card = (btn && btn.closest) ? btn.closest('.card') : null;
  if (!card) card = document.querySelector('#card-grid .card[data-name="' + _esc(filename) + '"]');
  _setCardWatched(card, on);
  var row = (btn && btn.closest) ? btn.closest('tr') : null;
  if (!row) row = document.querySelector('#tbody tr[data-name="' + _esc(filename) + '"]');
  _setRowWatched(row, on);
}
function markWatched(filename) {
  var w = getWatched();
  if (w[filename]) return;
  w[filename] = 1; setWatched(w);
  _setCardWatched(document.querySelector('#card-grid .card[data-name="' + _esc(filename) + '"]'), true);
  _setRowWatched(document.querySelector('#tbody tr[data-name="' + _esc(filename) + '"]'), true);
}
// Init: apply saved state on page load
(function() {
  var w = getWatched();
  Array.prototype.forEach.call(document.querySelectorAll('#card-grid .card'), function(c) {
    if (w[c.getAttribute('data-name')]) _setCardWatched(c, true);
  });
  Array.prototype.forEach.call(document.querySelectorAll('#tbody tr[data-name]'), function(r) {
    if (w[r.getAttribute('data-name')]) _setRowWatched(r, true);
  });
})();

// ── Background poster caching (browser downloads → server saves) ──────────────
(function() {
  var imgs = document.querySelectorAll('img.card-poster[data-cache-name]');
  if (!imgs.length) return;
  var dirParam = currentDir ? '&dir=' + encodeURIComponent(currentDir) : '';
  var queue = Array.prototype.slice.call(imgs);
  var running = 0, max = 4;
  function next() {
    while (running < max && queue.length) {
      running++;
      (function(img) {
        var name = img.getAttribute('data-cache-name');
        fetch(img.src, {mode:'cors', cache:'force-cache'})
          .then(function(r){ return r.blob(); })
          .then(function(blob){
            var fd = new FormData();
            fd.append('file', name);
            fd.append('img', blob, 'poster.jpg');
            return fetch('?action=cache_poster' + dirParam, {method:'POST', body:fd});
          })
          .catch(function(){ return null; })
          .then(function(){ running--; next(); });
      })(queue.shift());
    }
  }
  // Start after a short delay to not compete with initial page render
  setTimeout(next, 2000);
})();

// ── Movie info modal ──────────────────────────────────────────────────────────
function openMovieModal(meta) {
  var posterImg = document.getElementById('movie-modal-poster-img');
  var posterPh  = document.getElementById('movie-modal-poster-ph');
  // Prefer CDN w500 for high quality; fall back to local w300
  var posterSrc = meta.poster_path
    ? 'https://image.tmdb.org/t/p/w500' + meta.poster_path
    : meta.poster_local || '';
  if (posterSrc) {
    posterImg.src = posterSrc;
    posterImg.style.display = '';
    posterPh.style.display  = 'none';
  } else {
    posterImg.src = '';
    posterImg.style.display = 'none';
    posterPh.style.display  = '';
  }
  document.getElementById('movie-modal-title').textContent = meta.title || meta.filename;
  var metaParts = [];
  if (meta.year)     metaParts.push(meta.year);
  if (meta.filesize) metaParts.push(meta.filesize);
  if (meta.filename) metaParts.push(meta.filename);
  document.getElementById('movie-modal-meta').textContent = metaParts.join(' — ');
  document.getElementById('movie-modal-rating').innerHTML = meta.rating
    ? renderStars(meta.rating)
    : '<span class="no-rating">Pas de note</span>';
  document.getElementById('movie-modal-overview').textContent =
    meta.overview || 'Aucun résumé disponible.';
  var linksHtml = '';
  if (meta.tmdb_url)  linksHtml += '<a class="card-btn tmdb" href="' + escH(meta.tmdb_url) + '" target="_blank">TMDB</a>';
  if (meta.alloc_url) linksHtml += '<a class="card-btn allocine" href="' + escH(meta.alloc_url) + '" target="_blank">Allociné</a>';
  document.getElementById('movie-modal-links').innerHTML = linksHtml;
  openModal('movie-modal');
}

// Right-click on a card
document.addEventListener('contextmenu', function(e) {
  var card = e.target.closest ? e.target.closest('#card-grid .card') : null;
  if (!card) return;
  e.preventDefault();
  var metaStr = card.getAttribute('data-meta');
  if (!metaStr) return;
  try { openMovieModal(JSON.parse(metaStr)); } catch(ex) { console.warn(ex); }
});

// Long-press on a card (mobile)
(function() {
  var timer = null, duration = 600, target = null;
  document.addEventListener('touchstart', function(e) {
    var card = e.target.closest ? e.target.closest('#card-grid .card') : null;
    if (!card) return;
    target = card;
    timer  = setTimeout(function() {
      if (!target) return;
      var metaStr = target.getAttribute('data-meta');
      if (!metaStr) return;
      // Prevent the tap from triggering other events after the modal opens
      try { openMovieModal(JSON.parse(metaStr)); } catch(ex) { console.warn(ex); }
      target = null;
    }, duration);
  }, {passive: true});
  function cancel() { if (timer) { clearTimeout(timer); timer = null; } target = null; }
  document.addEventListener('touchend',    cancel);
  document.addEventListener('touchcancel', cancel);
  document.addEventListener('touchmove',   cancel, {passive: true});
})();

</script>
</body>
</html>
