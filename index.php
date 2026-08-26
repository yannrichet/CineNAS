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
function strm_token($rel) { return hash_hmac('sha256', $rel, FM_PASSWORD_HASH); }
function strm_token_valid($rel, $tok) { return hash_equals(strm_token($rel), (string)$tok); }

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
// Token-authenticated download (for .strm / VLC — no session needed)
if (isset($_GET['action']) && $_GET['action'] === 'download'
    && isset($_GET['token']) && isset($_GET['file'])) {
    $rel = $_GET['file'];
    if (strm_token_valid($rel, $_GET['token'])) {
        $f = jail($rel);
        if ($f && is_file($f)) {
            fm_send_file($f, 'application/octet-stream',
                'Content-Disposition: attachment; filename="' . addslashes(basename($f)) . '"');
        }
    }
    http_response_code(403); exit;
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
    // Callers already pass a value recovered from the 32-bit filesize()/stat()
    // wraparound via sprintf('%u', ...) — casting that (possibly >2GB) numeric
    // string through (int) here would clamp it straight back down to
    // PHP_INT_MAX (~2GB) on a 32-bit build, so go through float directly.
    $b = (float)$bytes;
    if ($b >= 1073741824) return round($b / 1073741824, 2) . ' GB';
    if ($b >= 1048576)    return round($b / 1048576, 1)    . ' MB';
    if ($b >= 1024)       return round($b / 1024, 1)       . ' KB';
    return $b . ' B';
}
// filesize() overflows to a negative/wrapped int for files >2GB on 32-bit PHP builds,
// which corrupts the Content-Length header sent to the browser/VLC and truncates
// downloads. clearstatcache() avoids a stale cached size, sprintf('%u', ...) undoes
// the 32-bit wraparound.
function fm_filesize($f) {
    clearstatcache(true, $f);
    return sprintf('%u', (int)filesize($f));
}
// Fresh (non-cached) size for a file in $dir, summing multi-part siblings
// (Movie.CD1.mkv + Movie.CD2.mkv) the same way the main listing does. Used to
// report an up-to-date size right after a manual TMDB re-sync, since the
// scan cache it invalidates only takes effect on the next full page load.
function fm_current_filesize($dir, $filename) {
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
    $pd  = detect_movie_parts($filename);
    if ($pd === null) {
        return (float)fm_filesize($dir . DIRECTORY_SEPARATOR . $filename);
    }
    $total = 0.0;
    $dh = @opendir($dir);
    if ($dh) {
        while (($e = readdir($dh)) !== false) {
            if (strtolower(pathinfo($e, PATHINFO_EXTENSION)) !== $ext) continue;
            $epd = detect_movie_parts($e);
            if ($epd && $epd['base'] === $pd['base']) {
                $total += (float)fm_filesize($dir . DIRECTORY_SEPARATOR . $e);
            }
        }
        closedir($dh);
    }
    return $total;
}
// Stream a file with HTTP Range support (RFC 7233). Without this, browsers doing
// resumable/parallel downloads and players seeking (VLC) send Range requests that
// were previously ignored — the server always replied with the *whole* file from
// byte 0 with a 200 status, so the client's range-based reassembly ended up with a
// truncated/wrong-size file regardless of how big it was.
function fm_send_file($path, $mime, $disposition_header, $cache_control = 'no-cache') {
    clearstatcache(true, $path);
    // filesize() wraps around to a negative int for files >2GB on 32-bit PHP
    // builds; sprintf('%u', ...) reinterprets that bit pattern as unsigned to
    // recover the true size, and casting to float (not int) keeps it intact —
    // this is what was still broken here (raw filesize() reached curl/browsers
    // as an invalid/negative Content-Length, truncating every large download).
    $size = (float)sprintf('%u', filesize($path));
    $fp   = fopen($path, 'rb');
    if ($size <= 0 || !$fp) { http_response_code(404); exit; }

    $start = 0.0;
    $end   = $size - 1;
    $status = 200;

    if (isset($_SERVER['HTTP_RANGE']) && preg_match('/bytes=(\d*)-(\d*)/', $_SERVER['HTTP_RANGE'], $m)) {
        $has_start = ($m[1] !== '');
        $has_end   = ($m[2] !== '');
        if ($has_start) { $start = (float)$m[1]; }
        if ($has_end)   { $end = (float)$m[2]; }
        elseif ($has_start) { $end = $size - 1; }
        else { // suffix range: bytes=-N
            $start = max(0, $size - (float)$m[2]);
            $end   = $size - 1;
        }
        if ($start > $end || $start >= $size || $end >= $size) {
            header('Content-Range: bytes */' . $size);
            http_response_code(416);
            fclose($fp); exit;
        }
        $status = 206;
    }

    http_response_code($status);
    header('Accept-Ranges: bytes');
    header('Content-Type: ' . $mime);
    header($disposition_header);
    header('Content-Length: ' . ($end - $start + 1));
    if ($status === 206) header('Content-Range: bytes ' . $start . '-' . $end . '/' . $size);
    header('Cache-Control: ' . $cache_control);

    fseek($fp, $start);
    $remaining = $end - $start + 1;
    $chunk = 1048576;
    while ($remaining > 0 && !feof($fp)) {
        $read = ($remaining > $chunk) ? $chunk : $remaining;
        echo fread($fp, $read);
        flush();
        $remaining -= $read;
    }
    fclose($fp);
    exit;
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

// ── Scan cache (avoids rescanning FM_ROOT + reloading every .movies_meta.json
//    on every single page load) ───────────────────────────────────────────────
define('SCAN_CACHE_FILE', FM_ROOT . DIRECTORY_SEPARATOR . '.scan_cache.json');
define('SCAN_CACHE_TTL',  60); // seconds; also invalidated immediately by scan_cache_clear()

function scan_cache_load() {
    if (!file_exists(SCAN_CACHE_FILE)) return null;
    if (time() - filemtime(SCAN_CACHE_FILE) > SCAN_CACHE_TTL) return null;
    $raw = @file_get_contents(SCAN_CACHE_FILE);
    if ($raw === false) return null;
    $data = json_decode($raw, true);
    return is_array($data) ? $data : null;
}
function scan_cache_save($data) {
    @file_put_contents(SCAN_CACHE_FILE, json_encode($data), LOCK_EX);
}
function scan_cache_clear() {
    @unlink(SCAN_CACHE_FILE);
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
// Returns 0-100: percentage of significant query words found in result_title.
// Used to flag low-confidence TMDB matches.
function title_confidence($query, $result_title) {
    $normalize = function($s) {
        $s = mb_strtolower($s, 'UTF-8');
        $s = preg_replace('/[^\p{L}\p{N}\s]/u', ' ', $s);
        $words = preg_split('/\s+/', trim($s), -1, PREG_SPLIT_NO_EMPTY);
        $stop = array('the','a','an','de','la','le','les','du','des','et','of','in','l','d','un','une');
        // Keep digits (episode/part numbers) and words > 2 chars
        return array_values(array_filter($words, function($w) use ($stop) {
            return (mb_strlen($w) > 2 || ctype_digit($w)) && !in_array($w, $stop);
        }));
    };
    $qw = $normalize($query);
    $rw = $normalize($result_title);
    if (empty($qw) || empty($rw)) return 50;
    $common = count(array_intersect($qw, $rw));
    // Dice coefficient: less harsh than max() for sequels with long subtitles
    return (int)round(200 * $common / (count($qw) + count($rw)));
}
function roman_to_arabic($s) {
    $map = array('CM'=>900,'M'=>1000,'CD'=>400,'D'=>500,'XC'=>90,'C'=>100,'XL'=>40,'L'=>50,'IX'=>9,'X'=>10,'IV'=>4,'V'=>5,'I'=>1);
    $s = strtoupper(trim($s));
    $n = 0;
    foreach ($map as $k => $v) {
        while (substr($s, 0, strlen($k)) === $k) { $n += $v; $s = substr($s, strlen($k)); }
    }
    return ($n > 0 && $s === '') ? $n : null;
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
    // Strip episode/season markers: Ep07, Ep7, S01E02, but NOT "Episode" (keep for TMDB)
    $title = preg_replace('/\bEp\d+\b/i', '', $title);
    $title = preg_replace('/\bS\d{1,2}E\d{1,2}\b/i', '', $title);
    // Replace dots and underscores with spaces
    $title = str_replace(array('.', '_'), ' ', $title);
    // Split CamelCase
    $title = preg_replace('/([a-z])([A-Z])/', '$1 $2', $title);
    $title = preg_replace('/\s{2,}/', ' ', $title);
    $title = trim($title);
    // Convert Roman numeral episode numbers: "Episode V" → "Episode 5" (better TMDB matching)
    $title = preg_replace_callback('/\bEpisode\s+([IVXLCDM]+)\b/i', function($m) {
        $n = roman_to_arabic($m[1]);
        return $n ? 'Episode ' . $n : $m[0];
    }, $title);
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
function tmdb_fetch_tv($series_title, $season, $episode, $year = null) {
    if (!FM_TMDB_API_KEY) return null;
    $ctx = stream_context_create(array('http' => array(
        'timeout' => 8,
        'ignore_errors' => true,
        'header' => 'Authorization: Bearer ' . FM_TMDB_API_KEY . "\r\n"
                  . 'Accept: application/json' . "\r\n",
    )));
    // 1. Search the TV show
    $query = urlencode($series_title);
    $url   = 'https://api.themoviedb.org/3/search/tv'
           . '?query=' . $query
           . '&language=' . FM_TMDB_LANG
           . ($year ? '&first_air_date_year=' . $year : '');
    $resp  = @file_get_contents($url, false, $ctx);
    if (!$resp) return null;
    $data  = json_decode($resp, true);
    if (empty($data['results'])) {
        // Retry without year
        if ($year) return tmdb_fetch_tv($series_title, $season, $episode, null);
        // Fallback to first 4 words
        $words = preg_split('/\s+/', trim($series_title));
        if (count($words) > 4) return tmdb_fetch_tv(implode(' ', array_slice($words, 0, 4)), $season, $episode, null);
        return null;
    }
    $show = $data['results'][0];
    $show_id = $show['id'];
    // 2. Fetch episode details
    $ep_url  = 'https://api.themoviedb.org/3/tv/' . $show_id
             . '/season/' . $season . '/episode/' . $episode
             . '?language=' . FM_TMDB_LANG;
    $ep_resp = @file_get_contents($ep_url, false, $ctx);
    $ep      = $ep_resp ? json_decode($ep_resp, true) : array();
    if (!empty($ep['status_code'])) $ep = array(); // TMDB error (e.g. episode not found)
    // 3. Fetch show genres (not in search results)
    $show_url  = 'https://api.themoviedb.org/3/tv/' . $show_id . '?language=' . FM_TMDB_LANG;
    $show_resp = @file_get_contents($show_url, false, $ctx);
    $show_full = $show_resp ? json_decode($show_resp, true) : array();
    $genre_ids = array();
    if (!empty($show_full['genres'])) {
        foreach ($show_full['genres'] as $g) $genre_ids[] = $g['id'];
    }
    // Episode poster (still image) > series poster
    $poster_path = '';
    if (!empty($ep['still_path']))  $poster_path = $ep['still_path'];
    elseif (!empty($show['poster_path'])) $poster_path = $show['poster_path'];
    // Episode title and overview fall back to series
    $ep_title    = !empty($ep['name'])     ? $ep['name']     : '';
    $ep_overview = !empty($ep['overview']) ? $ep['overview'] : (isset($show['overview']) ? $show['overview'] : '');
    $air_year    = !empty($ep['air_date']) ? (int)substr($ep['air_date'], 0, 4)
                 : (!empty($show['first_air_date']) ? (int)substr($show['first_air_date'], 0, 4) : $year);
    $show_name   = isset($show['name']) ? $show['name'] : $series_title;
    // Build display title: "Show Name — S01E03 · Episode Title"
    $ep_code = sprintf('S%02dE%02d', $season, $episode);
    $display_title = $ep_title ? $show_name . ' ' . $ep_code . ' · ' . $ep_title : $show_name . ' ' . $ep_code;
    return array(
        'tmdb_id'     => $show_id,
        'is_tv'       => true,
        'season'      => $season,
        'episode'     => $episode,
        'title'       => $display_title,
        'show_title'  => $show_name,
        'ep_title'    => $ep_title,
        'orig_title'  => isset($show['original_name']) ? $show['original_name'] : '',
        'year'        => $air_year,
        'poster_path' => $poster_path,
        'rating'      => isset($show['vote_average']) ? round($show['vote_average'], 1) : null,
        'votes'       => isset($show['vote_count'])   ? $show['vote_count'] : 0,
        'overview'    => $ep_overview,
        'genre_ids'   => $genre_ids,
        'fetched_at'  => time(),
        'confidence'  => 100,
    );
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
        // Fallback: try with only the first 4 words (handles noisy long titles)
        $words = preg_split('/\s+/', trim($title));
        if (count($words) > 4) {
            return tmdb_fetch(implode(' ', array_slice($words, 0, 4)), null);
        }
        return null;
    }
    $m = $data['results'][0];
    // If the query contains "Episode N" (Arabic), prefer a result whose title
    // also contains "Episode N" or "Episode <roman>" — avoids TMDB returning
    // the most popular film in a franchise instead of the specific episode.
    if (preg_match('/\bEpisode\s+(\d+)\b/i', $title, $ep)) {
        $ep_num = (int)$ep[1];
        $roman_map = array(1=>'I',2=>'II',3=>'III',4=>'IV',5=>'V',6=>'VI',7=>'VII',8=>'VIII',9=>'IX',10=>'X');
        $ep_roman  = isset($roman_map[$ep_num]) ? $roman_map[$ep_num] : null;
        foreach ($data['results'] as $candidate) {
            $ct = (isset($candidate['title']) ? $candidate['title'] : '') . ' '
                . (isset($candidate['original_title']) ? $candidate['original_title'] : '');
            $matched = preg_match('/\bEpisode\s+' . $ep_num . '\b/i', $ct)
                    || ($ep_roman && preg_match('/\bEpisode\s+' . preg_quote($ep_roman, '/') . '\b/i', $ct));
            if ($matched) { $m = $candidate; break; }
        }
    }
    $result_title = isset($m['title']) ? $m['title'] : (isset($m['original_title']) ? $m['original_title'] : '');
    return array(
        'tmdb_id'     => $m['id'],
        'title'       => isset($m['title'])          ? $m['title']          : $title,
        'orig_title'  => isset($m['original_title']) ? $m['original_title'] : '',
        'year'        => isset($m['release_date'])   ? (int)substr($m['release_date'], 0, 4) : $year,
        'poster_path' => isset($m['poster_path'])    ? $m['poster_path']    : '',
        'rating'      => isset($m['vote_average'])   ? round($m['vote_average'], 1) : null,
        'votes'       => isset($m['vote_count'])     ? $m['vote_count']     : 0,
        'overview'    => isset($m['overview'])       ? $m['overview']       : '',
        'genre_ids'   => isset($m['genre_ids'])      ? $m['genre_ids']      : array(),
        'fetched_at'  => time(),
        'confidence'  => title_confidence($title, $result_title),
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
        fm_send_file($f, 'application/octet-stream',
            'Content-Disposition: attachment; filename="' . addslashes(basename($f)) . '"');
    }
    http_response_code(404); exit;
}
if ($get_action === 'strm') {
    $rel = isset($_GET['file']) ? $_GET['file'] : '';
    $f   = jail($rel);
    if ($f && is_file($f)) {
        $scheme   = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') ? 'https' : 'http';
        $host     = $_SERVER['HTTP_HOST'];
        $script   = $_SERVER['SCRIPT_NAME'];
        $token    = strm_token($rel);
        $file_url = $scheme . '://' . $host . $script
                  . '?action=download&file=' . urlencode($rel)
                  . '&token=' . $token;
        $strm_name = pathinfo(basename($f), PATHINFO_FILENAME) . '.strm';
        header('Content-Type: application/octet-stream');
        header('Content-Disposition: attachment; filename="' . addslashes($strm_name) . '"');
        header('Cache-Control: no-cache');
        echo $file_url;
        exit;
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
        fm_send_file($f, $mime, 'Content-Disposition: inline', 'max-age=3600');
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
        scan_cache_clear();
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
    // Optional custom search title supplied by the user via the edit-title UI
    $custom_title = isset($_GET['custom_title']) ? trim($_GET['custom_title']) : '';
    if ($custom_title) {
        // Allow "Title (Year)" or "Title Year" notation in the custom title
        $parsed = array('title' => $custom_title, 'year' => null);
        if (preg_match('/\b((?:19|20)\d{2})\b/', $custom_title, $ym)) {
            $parsed['year']  = (int)$ym[1];
            $parsed['title'] = trim(preg_replace('/\b(?:19|20)\d{2}\b/', '', $custom_title));
        }
    } else {
        // Strip multi-part suffix before TMDB search so "Movie.CD1.mkv" searches
        // for "Movie" rather than "Movie CD1" (which TMDB can't match).
        $_pd_fetch = detect_movie_parts($filename);
        $search_name = ($_pd_fetch !== null)
            ? $_pd_fetch['base'] . '.' . pathinfo($filename, PATHINFO_EXTENSION)
            : $filename;
        $parsed = parse_movie_name($search_name);
    }

    // ── Route: TV episode (SxxExx in filename) vs movie ──────────────────────
    $is_tv_ep = preg_match('/\bS(\d{1,2})E(\d{1,2})\b/i', $filename, $_se_m);
    if ($is_tv_ep && !$custom_title) {
        $tv_season  = (int)$_se_m[1];
        $tv_episode = (int)$_se_m[2];
        // Extract series title: everything before the SxxExx marker
        $stem_tv = pathinfo($filename, PATHINFO_FILENAME);
        $stem_tv = preg_replace('/\bS\d{1,2}E\d{1,2}.*/i', '', $stem_tv);
        $stem_tv = str_replace(array('.', '_'), ' ', $stem_tv);
        $stem_tv = preg_replace('/([a-z])([A-Z])/', '$1 $2', $stem_tv);
        $stem_tv = trim(preg_replace('/\s{2,}/', ' ', $stem_tv));
        $result  = tmdb_fetch_tv($stem_tv, $tv_season, $tv_episode, $parsed['year']);
    } else {
        $result = tmdb_fetch($parsed['title'], $parsed['year']);
    }
    // If year was used and confidence is low, retry without year (movies only)
    if (!$is_tv_ep && $result && $parsed['year'] && isset($result['confidence']) && $result['confidence'] < 50) {
        $result_ny = tmdb_fetch($parsed['title'], null);
        if ($result_ny && isset($result_ny['confidence']) && $result_ny['confidence'] > $result['confidence']) {
            $result = $result_ny;
        }
    }
    $fresh_bytes = fm_current_filesize($ajax_cwd, $filename);
    if ($result) {
        if (!empty($result['poster_path'])) {
            $local = poster_download($result['poster_path'], $ajax_cwd);
            if ($local) $result['poster_local'] = $local;
        }
        if ($custom_title) $result['custom_title'] = $custom_title;
        $meta[$filename] = $result;
        meta_save($meta, $ajax_cwd);
        scan_cache_clear();
        $result['bytes']    = $fresh_bytes;
        $result['filesize'] = fmt_size($fresh_bytes);
        ob_clean(); header('Content-Type: application/json');
        echo json_encode(array('ok' => true, 'data' => $result));
    } else {
        $meta[$filename] = array('not_found' => true, 'fetched_at' => time());
        meta_save($meta, $ajax_cwd);
        scan_cache_clear();
        ob_clean(); header('Content-Type: application/json');
        echo json_encode(array('ok' => false, 'error' => 'Not found on TMDB', 'bytes' => $fresh_bytes, 'filesize' => fmt_size($fresh_bytes)));
    }
    exit;
}

// ── Rename file (AJAX, GET) ───────────────────────────────────────────────────
if ($get_action === 'rename_file') {
    header('Content-Type: application/json');
    $ajax_cwd = current_dir();
    $oldname  = isset($_GET['file'])    ? basename($_GET['file'])    : '';
    $newname  = isset($_GET['newname']) ? basename($_GET['newname']) : '';
    if (!$oldname || !$newname) { echo json_encode(array('ok'=>false,'error'=>'Paramètres manquants')); exit; }
    // Keep same extension
    $old_ext = strtolower(pathinfo($oldname, PATHINFO_EXTENSION));
    $new_ext = strtolower(pathinfo($newname, PATHINFO_EXTENSION));
    if (!$new_ext || $new_ext !== $old_ext) {
        $newname = pathinfo($newname, PATHINFO_FILENAME) . '.' . $old_ext;
    }
    if ($oldname === $newname) { echo json_encode(array('ok'=>true,'newfile'=>$newname)); exit; }
    $old_path = $ajax_cwd . DIRECTORY_SEPARATOR . $oldname;
    $new_path = $ajax_cwd . DIRECTORY_SEPARATOR . $newname;
    if (strncmp($old_path, FM_ROOT, strlen(FM_ROOT)) !== 0 ||
        strncmp($new_path, FM_ROOT, strlen(FM_ROOT)) !== 0) {
        echo json_encode(array('ok'=>false,'error'=>'Accès refusé')); exit;
    }
    if (!file_exists($old_path)) { echo json_encode(array('ok'=>false,'error'=>'Fichier introuvable')); exit; }
    if (file_exists($new_path))  { echo json_encode(array('ok'=>false,'error'=>'Un fichier avec ce nom existe déjà')); exit; }
    if (!@rename($old_path, $new_path)) { echo json_encode(array('ok'=>false,'error'=>'Renommage impossible')); exit; }
    scan_cache_clear();
    // Move meta entry to new key
    $meta = meta_load($ajax_cwd);
    if (isset($meta[$oldname])) {
        $meta[$newname] = $meta[$oldname];
        unset($meta[$oldname]);
        meta_save($meta, $ajax_cwd);
    }
    echo json_encode(array('ok'=>true,'newfile'=>$newname)); exit;
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
        scan_cache_clear();
    }
    echo json_encode(array('ok' => true)); exit;
}

if (!FM_DEMO_MODE && $_SERVER['REQUEST_METHOD'] === 'POST') {
    csrf_check();
    scan_cache_clear(); // upload/mkdir/delete/rename all change the file tree
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

// ── Scan ALL videos recursively from FM_ROOT ──────────────────────────────────
$cwd     = current_dir(); // still used by AJAX actions (fetch_meta, rename, etc.)
$cwd_rel = relpath($cwd);
$video_ext    = array('mkv','mp4','avi','mov','wmv','flv','mpg','mpeg','m4v','3gp','ts','webm','divx','xvid');
$subtitle_ext = array('srt','sub','ass','ssa','vtt');
$ignore      = array('.', '..', basename(__FILE__), '.DS_Store', 'Thumbs.db',
                 '.movies_meta.json', '.posters', '.@__thumb', '.@__qini', '@Transcode', '.deletedByTMM',
                 'listr.css', 'listr-favicon.png', 'index.php_old', 'filemanager.php',
                 basename(SCAN_CACHE_FILE));
$ignore_ext  = array('php', 'php3', 'php4', 'php5', 'phtml', 'sh', 'bash', 'py', 'pl', 'rb');
$all_files    = array();
$subs_by_base = array();
$total_bytes  = 0.0;
$meta_by_dir  = array(); // abs_dir => metadata array (lazy-loaded during scan)

function do_scan_recursive($dir, $tag) {
    global $all_files, $subs_by_base, $total_bytes, $meta_by_dir,
           $video_ext, $subtitle_ext, $ignore, $ignore_ext;
    if (!isset($meta_by_dir[$dir])) $meta_by_dir[$dir] = meta_load($dir);
    $dh = @opendir($dir);
    if (!$dh) return;
    while (($e = readdir($dh)) !== false) {
        if (in_array($e, $ignore, true)) continue;
        $ext_check = strtolower(pathinfo($e, PATHINFO_EXTENSION));
        if (in_array($ext_check, $ignore_ext, true)) continue;
        $abs = $dir . DIRECTORY_SEPARATOR . $e;
        if (is_dir($abs)) {
            // Use only the top-level subdirectory name as the tag
            $child_tag = ($tag === '') ? $e : $tag;
            do_scan_recursive($abs, $child_tag);
        } elseif (in_array($ext_check, $subtitle_ext, true)) {
            $rel  = str_replace(DIRECTORY_SEPARATOR, '/', ltrim(substr($abs, strlen(FM_ROOT)), DIRECTORY_SEPARATOR));
            $base = strtolower(pathinfo($e, PATHINFO_FILENAME));
            if (!isset($subs_by_base[$base])) $subs_by_base[$base] = array();
            $subs_by_base[$base][] = array('name' => $e, 'rel' => $rel, 'ext' => $ext_check);
        } elseif (in_array($ext_check, $video_ext, true)) {
            $stat  = @stat($abs);
            $bytes = ($stat && isset($stat['size'])) ? sprintf('%u', $stat['size']) : 0;
            $total_bytes += (float)$bytes;
            $rel   = str_replace(DIRECTORY_SEPARATOR, '/', ltrim(substr($abs, strlen(FM_ROOT)), DIRECTORY_SEPARATOR));
            $all_files[] = array(
                'name'  => $e,
                'rel'   => $rel,
                'mtime' => ($stat && isset($stat['mtime'])) ? $stat['mtime'] : 0,
                'bytes' => $bytes,
                'ext'   => $ext_check,
                'tag'   => $tag,
                'dir'   => $dir,
            );
        }
    }
    closedir($dh);
}
$_scan_cached = scan_cache_load();
if ($_scan_cached !== null) {
    $all_files    = $_scan_cached['all_files'];
    $subs_by_base = $_scan_cached['subs_by_base'];
    $total_bytes  = $_scan_cached['total_bytes'];
    $meta_by_dir  = $_scan_cached['meta_by_dir'];
} else {
    do_scan_recursive(FM_ROOT, '');
    usort($all_files, function($a, $b) { return $b['mtime'] - $a['mtime']; });
    scan_cache_save(array(
        'all_files'    => $all_files,
        'subs_by_base' => $subs_by_base,
        'total_bytes'  => $total_bytes,
        'meta_by_dir'  => $meta_by_dir,
    ));
}
$files = $all_files; // alias used in templates

// Collect unique sorted tags
$all_tags = array();
foreach ($all_files as $_f) {
    if ($_f['tag'] !== '' && !in_array($_f['tag'], $all_tags, true)) $all_tags[] = $_f['tag'];
}
sort($all_tags);

// ── Multi-part movie grouping (keyed by dir+base to avoid cross-dir collisions) ─
$parts_by_base = array();
foreach ($all_files as $_pf) {
    $_pd = detect_movie_parts($_pf['name']);
    if ($_pd === null) continue;
    $_key = $_pf['dir'] . '|' . strtolower($_pd['base']);
    if (!isset($parts_by_base[$_key])) $parts_by_base[$_key] = array();
    $parts_by_base[$_key][] = array_merge($_pf, array('part_num' => $_pd['part']));
}
foreach (array_keys($parts_by_base) as $_key) {
    if (count($parts_by_base[$_key]) < 2) { unset($parts_by_base[$_key]); continue; }
    usort($parts_by_base[$_key], function($a, $b) { return $a['part_num'] - $b['part_num']; });
}
$skip_files = array(); // rel => true, secondary parts hidden in main loops
foreach ($parts_by_base as $_group) {
    for ($_i = 1; $_i < count($_group); $_i++) $skip_files[$_group[$_i]['rel']] = true;
}

// ── TMDB genre map ─────────────────────────────────────────────────────────────
$tmdb_genres = array(
    28=>'Action', 12=>'Aventure', 16=>'Animation', 35=>'Comédie', 80=>'Crime',
    99=>'Documentaire', 18=>'Drame', 10751=>'Famille', 14=>'Fantastique', 36=>'Histoire',
    27=>'Horreur', 10402=>'Musique', 9648=>'Mystère', 10749=>'Romance',
    878=>'Science-Fiction', 10770=>'Téléfilm', 53=>'Thriller', 10752=>'Guerre', 37=>'Western',
);
// Collect genre IDs actually present in loaded metadata
$all_genre_ids_present = array();
foreach ($meta_by_dir as $_dir_meta) {
    foreach ($_dir_meta as $_fm) {
        if (!empty($_fm['genre_ids']) && is_array($_fm['genre_ids'])) {
            foreach ($_fm['genre_ids'] as $_gid) {
                if (!in_array($_gid, $all_genre_ids_present, true)) $all_genre_ids_present[] = (int)$_gid;
            }
        }
    }
}
sort($all_genre_ids_present);

$dir_url = '?'; // all forms target root

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
<title><?php echo FM_TITLE; ?></title>
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
         flex-wrap:wrap}
#tag-nav{display:flex;gap:.4rem;align-items:center;flex-wrap:wrap;}
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
.card-btn-play{background:#166534;color:#86efac;font-weight:600}
.card-btn-play:hover{background:#15803d;color:#dcfce7}
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
.card-bad-match {
  position:absolute;top:.5rem;left:.5rem;z-index:3;
  background:#f59e0b;color:#000;font-size:.75rem;font-weight:700;
  padding:.15rem .35rem;border-radius:.25rem;cursor:default;
  line-height:1;
}
.card--bad-match { outline:2px solid #f59e0b; }
.card-btn-edit { background:#6366f1; }
.card-btn-edit:hover { background:#4f46e5; }
.edit-title-overlay {
  position:fixed;inset:0;z-index:9999;background:rgba(0,0,0,.75);
  display:flex;align-items:center;justify-content:center;padding:1rem;
}
.edit-title-box {
  background:#111827;border:1px solid #374151;border-radius:.75rem;
  padding:1.5rem;width:100%;max-width:440px;color:#f9fafb;box-shadow:0 8px 32px rgba(0,0,0,.6);
}
.edit-title-box input[type=text] {
  width:100%;box-sizing:border-box;padding:.45rem .65rem;
  border:1px solid #374151;border-radius:.35rem;
  background:#1f2937;color:#f9fafb;font-size:.95rem;
}
.edit-title-box input[type=text]:focus { outline:none;border-color:#6366f1; }
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
/* ── Tag filter chips ── */
.tag-chip{display:inline-flex;align-items:center;gap:.3rem;padding:.3rem .65rem;
          background:#1e2533;color:#a78bfa;border-radius:20px;text-decoration:none;
          font-size:.78rem;font-weight:500;border:1px solid #374151;flex-shrink:0;cursor:pointer;
          transition:.15s;user-select:none}
.tag-chip:hover{background:#312e81;border-color:#6366f1;color:#fff}
.tag-chip.active{background:#4f46e5;border-color:#6366f1;color:#fff}
.tag-chip.excluded{background:#7f1d1d;border-color:#ef4444;color:#fca5a5}
.tag-chip.excluded:hover{background:#991b1b;border-color:#f87171;color:#fecaca}
/* ── Filter controls ── */
.filter-label{color:#6b7280;font-size:.76rem;flex-shrink:0}
.filter-btn{padding:.3rem .6rem;border-radius:4px;background:#1e2533;border:1px solid #374151;
            color:#9ca3af;cursor:pointer;font-size:.78rem;transition:.15s;flex-shrink:0}
.filter-btn:hover{background:#243044;border-color:#6366f1;color:#e5e7eb}
.filter-btn.active{background:#4f46e5;border-color:#6366f1;color:#fff}
.filter-select{background:#111827;border:1px solid #374151;border-radius:4px;
               color:#e5e7eb;padding:.3rem .5rem;font-size:.78rem;cursor:pointer;flex-shrink:0}
.filter-sep{width:1px;height:18px;background:#374151;flex-shrink:0}
/* ── Tag badge on cards ── */
.tag-badge{display:inline-block;padding:.1rem .35rem;background:#1e3a5f;color:#93c5fd;
           border-radius:3px;font-size:.62rem;font-weight:500;cursor:pointer;margin-right:.2rem}
.tag-badge:hover{background:#1e40af;color:#bfdbfe}
/* ── Tag column in table ── */
.col-tag{white-space:nowrap;color:#93c5fd;font-size:.76rem}
@media(max-width:600px){
  .filter-btn{font-size:.7rem;padding:.18rem .4rem}
  .filter-select{font-size:.7rem}
  .col-tag{display:none}
  .filter-sep{display:none}
}
</style>
</head>
<body>
<div id="app">

<div id="toolbar">
  <a class="home-chip" href="?" title="Accueil">🏠</a>
  <div id="tag-nav">
    <button class="tag-chip active" data-tag-value="">Tous</button>
    <?php foreach ($all_tags as $_tag): ?>
    <button class="tag-chip" data-tag-value="<?php echo h($_tag); ?>"><?php echo h($_tag); ?></button>
    <?php endforeach; ?>
  </div>
  <div class="filter-sep"></div>
  <button class="filter-btn" id="btn-watched" onclick="cycleWatchedFilter()" title="Filtrer par statut">👁 Tous</button>
  <div class="filter-sep"></div>
  <select class="filter-select" id="filter-rating" onchange="setRatingFilter(this.value)" title="Note minimum">
    <option value="0">⭐ Toutes notes</option>
    <option value="4">⭐ ≥ 4</option>
    <option value="5">⭐ ≥ 5</option>
    <option value="6">⭐ ≥ 6</option>
    <option value="7">⭐ ≥ 7</option>
    <option value="8">⭐ ≥ 8</option>
  </select>
  <?php if (!empty($all_genre_ids_present)): ?>
  <select class="filter-select" id="filter-genre" onchange="setGenreFilter(this.value)" title="Genre">
    <option value="0">🎭 Tous genres</option>
    <?php foreach ($all_genre_ids_present as $_gid): ?>
    <?php if (isset($tmdb_genres[$_gid])): ?>
    <option value="<?php echo (int)$_gid; ?>"><?php echo h($tmdb_genres[$_gid]); ?></option>
    <?php endif; ?>
    <?php endforeach; ?>
  </select>
  <?php endif; ?>
  <div class="filter-sep"></div>
  <?php if (FM_TMDB_API_KEY): ?>
  <button class="btn btn-secondary" id="btn-sync" onclick="startSync()">🎬 Sync</button>
  <?php endif; ?>
  <button class="btn btn-secondary" id="btn-list" onclick="setView('list')" title="Vue liste">☰</button>
  <button class="btn btn-secondary" id="btn-grid" onclick="setView('grid')" title="Vue grille">⊞</button>
  <input type="search" id="search" placeholder="Rechercher…" oninput="filterAll()" autocomplete="off">
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
  $m      = isset($meta_by_dir[$item['dir']][$item['name']]) ? $meta_by_dir[$item['dir']][$item['name']] : null;
  $is_vid = in_array($item['ext'], $video_ext, true);
  if (!$is_vid) continue;
  if (isset($skip_files[$item['rel']])) continue; // secondary part — shown on primary card
  // Multi-part: collect all parts for this film (sorted by part number)
  $_pd_card   = detect_movie_parts($item['name']);
  $_parts_key = ($_pd_card !== null) ? ($item['dir'] . '|' . strtolower($_pd_card['base'])) : null;
  $film_parts = ($_parts_key !== null && isset($parts_by_base[$_parts_key]))
              ? $parts_by_base[$_parts_key]
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
  $_card_genre_ids = ($m && !empty($m['genre_ids'])) ? $m['genre_ids'] : array();
  $_card_rating    = ($m && isset($m['rating'])) ? (float)$m['rating'] : 0;
  $_card_dir_rel   = ltrim(str_replace(DIRECTORY_SEPARATOR, '/', ltrim(substr($item['dir'], strlen(FM_ROOT)), DIRECTORY_SEPARATOR)), '/');
  $_card_ptype     = previewable($item['ext']);
  // Table view is built client-side from this data (see buildTableFromCards() in <script>)
  // instead of being rendered a second time server-side — avoids doubling the PHP render cost.
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
    'bytes'        => $film_bytes,
    'mtime'        => $item['mtime'],
    'date_disp'    => date('Y-m-d H:i', $item['mtime']),
    'icon'         => file_icon($item['ext']),
    'ptype'        => $_card_ptype,
    'has_title'    => (bool)($m && !empty($m['title'])),
    'parts'        => count($film_parts) > 0 ? count($film_parts) : 1,
    'parts_detail' => array_map(function($p) { return array('rel' => $p['rel'], 'name' => $p['name']); }, $film_parts),
    'subs'         => array_map(function($s) { return array('rel' => $s['rel'], 'name' => $s['name'], 'ext' => $s['ext']); }, $subs),
    'genre_ids'    => $_card_genre_ids,
    'tag'          => $item['tag'],
  ));
?>
<?php
  $not_found = ($m && !empty($m['not_found']));
  $confidence = ($m && isset($m['confidence'])) ? (int)$m['confidence'] : ($m ? 100 : -1);
  $bad_match  = (!$not_found && $m && $confidence >= 0 && $confidence < 45);
?>
<div class="card<?php echo $bad_match ? ' card--bad-match' : ''; ?>"
     data-name="<?php echo h($item['name']); ?>"
     data-rel="<?php echo h($item['rel']); ?>"
     data-tag="<?php echo h($item['tag']); ?>"
     data-rating="<?php echo $_card_rating; ?>"
     data-genre-ids="<?php echo h(json_encode($_card_genre_ids)); ?>"
     id="card-<?php echo md5($item['rel']); ?>"
     data-meta="<?php echo h($card_meta); ?>">
  <span class="card-watched-badge">✓ Vu</span>
  <?php if ($poster): ?>
    <img class="card-poster" src="<?php echo h($poster); ?>" alt=""<?php if (empty($m['poster_local']) && !empty($m['poster_path'])): ?> crossorigin="anonymous" data-cache-name="<?php echo h($item['name']); ?>" data-cache-dir="<?php echo h($_card_dir_rel); ?>"<?php endif; ?>>
  <?php else: ?>
    <div class="card-poster-placeholder">🎬</div>
  <?php endif; ?>
  <?php if ($not_found): ?>
    <span class="card-not-found" title="Non trouvé sur TMDB">?</span>
  <?php elseif ($bad_match): ?>
    <span class="card-bad-match" title="Identification TMDB incertaine (<?php echo $confidence; ?>% de correspondance) — cliquez ✎ pour corriger">⚠</span>
  <?php endif; ?>
  <div class="card-body">
    <?php if ($item['tag'] !== ''): ?>
    <div><span class="tag-badge" onclick="setTagFilter(<?php echo h(json_encode($item['tag'])); ?>)" title="Filtrer par ce tag"><?php echo h($item['tag']); ?></span></div>
    <?php endif; ?>
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
    <a class="card-btn card-btn-play" href="?action=strm&amp;file=<?php echo urlencode($item['rel']); ?>" title="Lire dans VLC/Kodi/Infuse (.strm)">▶ Lire</a>
    <a class="card-btn" href="?action=download&amp;file=<?php echo urlencode($item['rel']); ?>" onclick="markWatched(<?php echo h(json_encode($item['name'])); ?>)">⬇ Film</a>
    <?php else: ?>
    <?php foreach ($film_parts as $_pi => $_part): ?>
    <a class="card-btn card-btn-play" href="?action=strm&amp;file=<?php echo urlencode($_part['rel']); ?>" title="Lire partie <?php echo ($_pi+1); ?> dans VLC/Kodi/Infuse">▶<?php echo ($_pi+1); ?></a>
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
    <button class="card-btn card-btn-refresh" onclick="syncOne(this,<?php echo h(json_encode($item['rel'])); ?>)" title="Re-chercher sur TMDB">↺</button>
    <?php endif; ?>
  </div>
</div>
<?php endforeach; ?>
<?php endif; ?>
</div>

<div id="file-table-wrap">
<?php if (empty($files)): ?>
  <div class="empty"><span>🌑</span>Aucun film trouvé.</div>
<?php else: ?>

<table id="ftable">
<thead>
  <tr>
    <th class="col-icon"></th>
    <th class="col-name"    onclick="sortTable(this,1)">Nom <span class="si"></span></th>
    <th class="col-tag">Tag</th>
    <th class="col-size"    onclick="sortTable(this,3)">Taille <span class="si"></span></th>
    <th class="col-date"    onclick="sortTable(this,4)">Date <span class="si"></span></th>
    <th class="col-actions">Actions</th>
  </tr>
</thead>
<tbody id="tbody">
<!-- Rows are built client-side by buildTableFromCards() from the #card-grid .card
     data-meta already sent above — avoids rendering every file a second time in PHP. -->
</tbody>
</table>
<?php endif; ?>
</div>

<div id="footer">
  <span>🎬 <strong>CineNAS</strong> — <a href="https://github.com/yannrichet/CineNAS" target="_blank" rel="noopener" style="color:#6366f1;text-decoration:none">github.com/yannrichet/CineNAS</a><?php echo FM_DEMO_MODE ? ' — <em>Read-only mode</em>' : ''; ?></span>
  <span id="visible-count" style="color:#6b7280;font-size:.78rem"></span>
  <span><?php echo count($all_files); ?> films au total</span>
  <span style="color:#6b7280;font-size:.78rem">maj <?php echo date('d/m/Y H:i', filemtime(__FILE__)); ?></span>
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
// ── Build the table view from the card grid's data-meta ──────────────────────
// The server renders each film once (as a .card in #card-grid); the table view
// is derived from that same data client-side instead of being rendered a
// second time in PHP, so the page doesn't ship (and the server doesn't build)
// duplicate markup for every file.
function escAttr(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;')
                   .replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}
function buildTableFromCards() {
  var tbody = document.getElementById('tbody');
  if (!tbody) return;
  var cards = document.querySelectorAll('#card-grid .card');
  var html = '';
  for (var i = 0; i < cards.length; i++) {
    var card = cards[i];
    var name   = card.getAttribute('data-name') || '';
    var rel    = card.getAttribute('data-rel')  || '';
    var tag    = card.getAttribute('data-tag')  || '';
    var rating = card.getAttribute('data-rating') || '0';
    var gids   = card.getAttribute('data-genre-ids') || '[]';
    var meta = {}; try { meta = JSON.parse(card.getAttribute('data-meta') || '{}'); } catch(e) {}
    var parts = meta.parts_detail || [];
    var subs  = meta.subs || [];

    var nameCell;
    if (meta.ptype) {
      nameCell = '<a href="#" onclick="openPreview(' + escAttr(JSON.stringify(rel)) + ',' +
                 escAttr(JSON.stringify(name)) + ',' + escAttr(JSON.stringify(meta.ptype)) +
                 ');return false">' + escAttr(name) + '</a>';
    } else {
      nameCell = '<a href="?action=download&file=' + encodeURIComponent(rel) + '">' + escAttr(name) + '</a>';
    }
    if (meta.has_title) {
      nameCell += '<br><small style="color:#9ca3af">' + escAttr(meta.title) +
        (meta.year ? ' (' + meta.year + ')' : '') +
        (meta.rating !== null && meta.rating !== undefined ? ' — ' + meta.rating + '/10' : '') +
        '</small>';
    }

    var tagCell = tag !== ''
      ? '<span class="tag-badge" onclick="setTagFilter(' + escAttr(JSON.stringify(tag)) + ')" title="Filtrer par ce tag">' + escAttr(tag) + '</span>'
      : '';

    var sizeSuffix = parts.length > 0 ? ' <small style="color:#6b7280">(' + parts.length + '×)</small>' : '';

    var actions = '';
    if (parts.length > 0) {
      for (var pi = 0; pi < parts.length; pi++) {
        var p = parts[pi];
        actions += '<a class="btn btn-primary btn-sm" href="?action=strm&file=' + encodeURIComponent(p.rel) + '" title="Lire partie ' + (pi+1) + '">▶' + (pi+1) + '</a>';
        actions += '<a class="btn btn-secondary btn-sm" href="?action=download&file=' + encodeURIComponent(p.rel) + '" onclick="markWatched(' + escAttr(JSON.stringify(name)) + ')" title="' + escAttr(p.name) + '">⬇' + (pi+1) + '</a>';
      }
    } else {
      actions += '<a class="btn btn-primary btn-sm" href="?action=strm&file=' + encodeURIComponent(rel) + '" title="Lire dans VLC/Kodi/Infuse (.strm)">▶</a>';
      actions += '<a class="btn btn-secondary btn-sm" href="?action=download&file=' + encodeURIComponent(rel) + '" onclick="markWatched(' + escAttr(JSON.stringify(name)) + ')" title="⬇ Film">⬇</a>';
    }
    for (var si = 0; si < subs.length; si++) {
      var s = subs[si];
      actions += '<a class="btn btn-secondary btn-sm" href="?action=download&file=' + encodeURIComponent(s.rel) + '" title="' + escAttr(s.name) + '">💬</a>';
    }
    if (meta.ptype) {
      actions += '<button class="btn btn-secondary btn-sm" onclick="openPreview(' +
        escAttr(JSON.stringify(rel)) + ',' + escAttr(JSON.stringify(name)) + ',' + escAttr(JSON.stringify(meta.ptype)) +
        ')">▶</button>';
    }
    actions += '<button class="btn btn-secondary btn-sm btn-watch-row" onclick="toggleWatched(this,' + escAttr(JSON.stringify(name)) + ')" title="Marquer comme vu">👁</button>';

    html += '<tr data-name="' + escAttr(name) + '" data-rel="' + escAttr(rel) + '" data-tag="' + escAttr(tag) +
      '" data-rating="' + escAttr(rating) + '" data-genre-ids="' + escAttr(gids) + '">' +
      '<td class="col-icon">' + (meta.icon || '🎬') + '</td>' +
      '<td class="col-name" data-val="' + escAttr(name) + '">' + nameCell + '</td>' +
      '<td class="col-tag">' + tagCell + '</td>' +
      '<td class="col-size" data-val="' + (meta.bytes || 0) + '">' + escAttr(meta.filesize || '') + sizeSuffix + '</td>' +
      '<td class="col-date" data-val="' + (meta.mtime || 0) + '">' + escAttr(meta.date_disp || '') + '</td>' +
      '<td class="col-actions">' + actions + '</td>' +
      '</tr>';
  }
  tbody.innerHTML = html;
}
buildTableFromCards();

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

function filterAll() {
  var q = (document.getElementById('search').value || '').toLowerCase();
  var w = getWatched();
  var cards = document.querySelectorAll('#card-grid .card');
  for (var i = 0; i < cards.length; i++) {
    var card = cards[i];
    var name = card.getAttribute('data-name') || '';
    var tag  = card.getAttribute('data-tag')  || '';
    var rtg  = parseFloat(card.getAttribute('data-rating') || '0') || 0;
    var gids = []; try { gids = JSON.parse(card.getAttribute('data-genre-ids') || '[]'); } catch(e) {}
    var watched = !!w[name];
    var show = true;
    if (q) {
      var metaObj = {}; try { metaObj = JSON.parse(card.getAttribute('data-meta') || '{}'); } catch(e) {}
      var haystack = name.toLowerCase() + ' ' + (metaObj.title || '').toLowerCase();
      if (haystack.indexOf(q) === -1) show = false;
    }
    if (show && activeRating  && (rtg === 0 || rtg < activeRating))                  show = false;
    if (show && activeWatched === 'watched'   && !watched)                            show = false;
    if (show && activeWatched === 'unwatched' &&  watched)                            show = false;
    if (show && activeGenre   && gids.indexOf(activeGenre) === -1)                   show = false;
    // Tag filter: included tags (must match one) + excluded tags (must match none)
    if (show) {
      var incTags = Object.keys(tagStates).filter(function(t){return tagStates[t]==='include';});
      var exTags  = Object.keys(tagStates).filter(function(t){return tagStates[t]==='exclude';});
      if (incTags.length && incTags.indexOf(tag) === -1) show = false;
      if (show && exTags.indexOf(tag) !== -1) show = false;
    }
    card.style.display = show ? '' : 'none';
  }
  var rows = document.querySelectorAll('#tbody tr[data-name]');
  for (var j = 0; j < rows.length; j++) {
    var row  = rows[j];
    var rname   = row.getAttribute('data-name') || '';
    var rtag    = row.getAttribute('data-tag')  || '';
    var rrtg    = parseFloat(row.getAttribute('data-rating') || '0') || 0;
    var rgids   = []; try { rgids = JSON.parse(row.getAttribute('data-genre-ids') || '[]'); } catch(e) {}
    var rwatched = !!w[rname];
    var rshow = true;
    if (q && rname.toLowerCase().indexOf(q) === -1) rshow = false;
    if (rshow && activeRating  && (rrtg === 0 || rrtg < activeRating))                rshow = false;
    if (rshow && activeWatched === 'watched'   && !rwatched)                           rshow = false;
    if (rshow && activeWatched === 'unwatched' &&  rwatched)                           rshow = false;
    if (rshow && activeGenre   && rgids.indexOf(activeGenre) === -1)                  rshow = false;
    if (rshow) {
      var rincTags = Object.keys(tagStates).filter(function(t){return tagStates[t]==='include';});
      var rexTags  = Object.keys(tagStates).filter(function(t){return tagStates[t]==='exclude';});
      if (rincTags.length && rincTags.indexOf(rtag) === -1) rshow = false;
      if (rshow && rexTags.indexOf(rtag) !== -1) rshow = false;
    }
    if (rshow) row.className = row.className.replace(' row-hidden','');
    else if (row.className.indexOf('row-hidden') === -1) row.className += ' row-hidden';
  }
  // Update visible count badge
  var visCards = 0;
  for (var k = 0; k < cards.length; k++) if (cards[k].style.display !== 'none') visCards++;
  var el = document.getElementById('visible-count');
  if (el) el.textContent = visCards + ' film' + (visCards !== 1 ? 's' : '') + ' affichés';
}
function filterRows(q) { filterAll(); } // backward compat

// ── Tag filter ──
var ALL_TAGS     = <?php echo json_encode(array_values($all_tags)); ?>;
var tagStates    = {};   // tag → 'include' | 'exclude'
var activeRating  = 0;
var activeWatched = 'unwatched';
var activeGenre   = 0;

function _updateTagChips() {
  var hasInc = Object.keys(tagStates).some(function(t){return tagStates[t]==='include';});
  var hasAny = Object.keys(tagStates).length > 0;
  document.querySelectorAll('.tag-chip').forEach(function(c) {
    var v = c.getAttribute('data-tag-value');
    if (v === '') {
      // "Tous" chip: active only when nothing is filtered
      c.classList.toggle('active',    !hasAny);
      c.classList.remove('excluded');
    } else {
      var st = tagStates[v];
      c.classList.toggle('active',    st === 'include');
      c.classList.toggle('excluded',  st === 'exclude');
    }
  });
}

function setTagFilter(tag) {
  if (tag === '') {
    // "Tous" resets all tag states to neutral (no filter)
    tagStates = {};
  } else {
    var cur = tagStates[tag];
    if (!cur)               tagStates[tag] = 'exclude';
    else if (cur==='exclude') tagStates[tag] = 'include';
    else                    delete tagStates[tag];
  }
  _updateTagChips();
  filterAll();
}

// Wire up tag chip clicks + apply defaults / URL params on load
document.addEventListener('DOMContentLoaded', function() {
  document.querySelectorAll('.tag-chip').forEach(function(c) {
    c.addEventListener('click', function() {
      setTagFilter(c.getAttribute('data-tag-value') || '');
    });
  });

  // Parse URL params
  var urlParams = new URLSearchParams(window.location.search);
  var urlTag     = urlParams.get('tag');     // e.g. ?tag=007
  var urlWatched = urlParams.get('watched'); // e.g. ?watched=all

  // ── Initialise tags ──
  // Default: all tags excluded; if URL specifies a tag, only that one is included
  ALL_TAGS.forEach(function(t) { tagStates[t] = 'exclude'; });
  if (urlTag && ALL_TAGS.indexOf(urlTag) !== -1) {
    // Positive filter from URL: include only the requested tag
    ALL_TAGS.forEach(function(t) { tagStates[t] = t === urlTag ? 'include' : 'exclude'; });
  }
  _updateTagChips();

  // ── Initialise watched filter ──
  var initWatched = (urlWatched === 'all' || urlWatched === 'watched' || urlWatched === 'unwatched')
                    ? urlWatched : 'unwatched';
  activeWatched = initWatched;
  _updateWatchedBtn();

  filterAll();
});

var _watchedCycle = ['all', 'unwatched', 'watched'];
var _watchedLabel = { all: '👁 Tous', unwatched: '👁 Non vus', watched: '👁 Vus' };

function _updateWatchedBtn() {
  var btn = document.getElementById('btn-watched');
  if (!btn) return;
  btn.textContent = _watchedLabel[activeWatched] || '👁 Tous';
  btn.classList.toggle('active', activeWatched !== 'all');
}

function cycleWatchedFilter() {
  var idx = _watchedCycle.indexOf(activeWatched);
  activeWatched = _watchedCycle[(idx + 1) % _watchedCycle.length];
  _updateWatchedBtn();
  filterAll();
}

function setWatchedFilter(val) {
  activeWatched = val;
  _updateWatchedBtn();
  filterAll();
}
function setRatingFilter(val) {
  activeRating = parseFloat(val) || 0;
  filterAll();
}
function setGenreFilter(val) {
  activeGenre = parseInt(val) || 0;
  filterAll();
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
function _relToDir(rel) {
  var parts = rel.split('/');
  return parts.length > 1 ? parts.slice(0, -1).join('/') : '';
}
function fetchOne(fileRel, customTitle) {
  var parts    = fileRel.split('/');
  var filename = parts[parts.length - 1];
  var fileDir  = _relToDir(fileRel);
  var dirParam = fileDir ? '&dir=' + encodeURIComponent(fileDir) : '';
  var ctParam  = customTitle ? '&custom_title=' + encodeURIComponent(customTitle) : '';
  return fetch('?action=fetch_meta&file=' + encodeURIComponent(filename) + dirParam + ctParam)
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

function syncOne(btn, fileRel) {
  btn.disabled = true;
  btn.textContent = '⏳';
  fetchOne(fileRel).then(function(data) {
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
    var sizeText = d.filesize || '';
    if (!sizeText) {
      var yr = body.querySelector('.card-year');
      if (yr) { var parts = yr.textContent.split('—'); sizeText = parts.length > 1 ? parts[1].trim() : ''; }
    }
    var stars = d.rating ? '<div class="card-rating">' + renderStars(d.rating) + '</div>' : '';
    var ov    = d.overview ? '<div class="card-overview">' + escH(d.overview) + '</div>' : '';
    body.innerHTML = '<div class="card-title">' + escH(d.title || filename) + '</div>'
                   + '<div class="card-year">' + (d.year || '') + (sizeText ? ' — ' + sizeText : '') + '</div>'
                   + stars + ov;
  }
  var meta = {};
  try { meta = JSON.parse(card.getAttribute('data-meta') || '{}'); } catch(e) {}
  meta.title = d.title || filename;
  meta.year = d.year || null;
  meta.rating = typeof d.rating !== 'undefined' ? d.rating : null;
  meta.overview = d.overview || '';
  meta.poster_path = d.poster_path || '';
  meta.poster_local = d.poster_local || '';
  if (d.filesize) { meta.filesize = d.filesize; meta.bytes = d.bytes || 0; }
  meta.filename = meta.filename || filename;
  meta.alloc_url = 'https://www.allocine.fr/rechercher/movie/?q=' + encodeURIComponent(meta.title);
  if (d.tmdb_id) meta.tmdb_url = 'https://www.themoviedb.org/movie/' + d.tmdb_id;
  card.setAttribute('data-meta', JSON.stringify(meta));
  // Remove "not found" and "bad match" badges if present
  var nf = card.querySelector('.card-not-found');
  if (nf) nf.parentNode.removeChild(nf);
  var bm = card.querySelector('.card-bad-match');
  if (bm) bm.parentNode.removeChild(bm);
  card.classList.remove('card--bad-match');
}

function editMovieTitle(editBtn, fileRel) {
  var parts    = fileRel.split('/');
  var filename = parts[parts.length - 1];
  var fileDir  = _relToDir(fileRel);
  var dirParam = fileDir ? '&dir=' + encodeURIComponent(fileDir) : '';
  var card = editBtn.closest ? editBtn.closest('.card') : null;
  // Pre-fill with filename stem (without extension)
  var stem = filename.replace(/\.[^.]+$/, '');
  var overlay = document.createElement('div');
  overlay.className = 'edit-title-overlay';
  overlay.innerHTML = '<div class="edit-title-box">'
    + '<p style="margin:0 0 .75rem;font-weight:600;font-size:1rem">✎ Renommer le fichier</p>'
    + '<p style="margin:0 0 .4rem;font-size:.8rem;color:#9ca3af">Ancien nom&nbsp;: <em>' + escH(filename) + '</em></p>'
    + '<input type="text" id="edit-title-input" value="' + escH(stem) + '" autocomplete="off" spellcheck="false">'
    + '<p style="margin:.35rem 0 .75rem;font-size:.75rem;color:#6b7280">L\'extension est conservée automatiquement.<br>Conseil : inclure l\'année pour TMDB, ex&nbsp;: <em>Star Wars Episode 5 1980</em></p>'
    + '<div id="edit-title-error" style="display:none;color:#f87171;font-size:.8rem;margin-bottom:.5rem"></div>'
    + '<div style="display:flex;gap:.5rem;justify-content:flex-end">'
    + '<button id="edit-title-cancel" class="btn btn-secondary" style="font-size:.85rem;padding:.3rem .75rem">Annuler</button>'
    + '<button id="edit-title-confirm" class="btn btn-primary" style="font-size:.85rem;padding:.3rem .75rem">Renommer &amp; Sync ↺</button>'
    + '</div></div>';
  document.body.appendChild(overlay);
  var input   = document.getElementById('edit-title-input');
  var errDiv  = document.getElementById('edit-title-error');
  input.focus(); input.select();
  function doRename() {
    var newStem = input.value.trim();
    if (!newStem) return;
    var confirmBtn = document.getElementById('edit-title-confirm');
    confirmBtn.disabled = true;
    confirmBtn.textContent = '⏳';
    errDiv.style.display = 'none';
    fetch('?action=rename_file&file=' + encodeURIComponent(filename)
        + '&newname=' + encodeURIComponent(newStem) + dirParam)
      .then(function(r){ return r.json(); })
      .then(function(data) {
        if (!data.ok) {
          errDiv.textContent = data.error || 'Erreur inconnue';
          errDiv.style.display = '';
          confirmBtn.disabled = false;
          confirmBtn.textContent = 'Renommer & Sync ↺';
          return;
        }
        document.body.removeChild(overlay);
        // Trigger TMDB sync on the new filename then reload
        var newfile = data.newfile;
        fetch('?action=fetch_meta&file=' + encodeURIComponent(newfile) + dirParam)
          .catch(function(){})
          .then(function(){ location.reload(); });
      })
      .catch(function(e) {
        errDiv.textContent = 'Erreur réseau : ' + e;
        errDiv.style.display = '';
        confirmBtn.disabled = false;
        confirmBtn.textContent = 'Renommer & Sync ↺';
      });
  }
  document.getElementById('edit-title-cancel').onclick = function() { document.body.removeChild(overlay); };
  document.getElementById('edit-title-confirm').onclick = doRename;
  input.addEventListener('keydown', function(e) {
    if (e.key === 'Enter')  doRename();
    if (e.key === 'Escape') document.body.removeChild(overlay);
  });
  overlay.addEventListener('click', function(e) {
    if (e.target === overlay) document.body.removeChild(overlay);
  });
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
    if (cards[i].style.display === 'none') continue;  // skip filtered-out films
    var rel         = cards[i].getAttribute('data-rel');
    var hasPoster   = cards[i].querySelector('.card-poster');
    var isBadMatch  = cards[i].classList.contains('card--bad-match');
    var isNotFound  = cards[i].querySelector('.card-not-found');
    if (rel && (!hasPoster || isBadMatch || isNotFound)) syncQueue.push(rel);
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
  var fileRel  = syncQueue.shift();
  var filename = fileRel.split('/').pop();
  syncDone++;
  document.getElementById('sync-progress').textContent =
    syncDone + '/' + syncTotal + ' — ' + filename;
  fetchOne(fileRel).then(function(){ setTimeout(syncNext, 300); }).catch(function(e) {
    console.warn('Sync error for ' + fileRel + ':', e);
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
  // Initial filter run to populate visible count
  filterAll();
})();

// ── Background poster caching (browser downloads → server saves) ──────────────
(function() {
  var imgs = document.querySelectorAll('img.card-poster[data-cache-name]');
  if (!imgs.length) return;
  var queue = Array.prototype.slice.call(imgs);
  var running = 0, max = 4;
  function next() {
    while (running < max && queue.length) {
      running++;
      (function(img) {
        var name    = img.getAttribute('data-cache-name');
        var cacheDir = img.getAttribute('data-cache-dir') || '';
        var dirParam = cacheDir ? '&dir=' + encodeURIComponent(cacheDir) : '';
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
