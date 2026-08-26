<?php
// Diagnostic temporaire — pas utilisé par l'appli, uniquement pour ce conteneur.
header('Content-Type: text/plain; charset=utf-8');

echo "PHP_INT_SIZE  = " . PHP_INT_SIZE . " (4 = PHP 32-bit, 8 = PHP 64-bit)\n";
echo "PHP_INT_MAX   = " . PHP_INT_MAX . "\n";
echo "PHP_VERSION   = " . PHP_VERSION . "\n";
echo "php_sapi_name = " . php_sapi_name() . "\n\n";

$file = isset($_GET['file']) ? $_GET['file'] : (__DIR__ . '/testfile.mkv');
if (!is_file($file)) {
    echo "Fichier introuvable ou pas un fichier: $file\n";
    exit;
}

clearstatcache(true, $file);
$fs = filesize($file);
echo "filesize() brut         = "; var_dump($fs);

$st = stat($file);
echo "stat()['size'] brut     = "; var_dump($st['size']);

echo "sprintf('%u', filesize) = " . sprintf('%u', $fs) . "\n";
echo "sprintf('%u', (int)fs)  = " . sprintf('%u', (int)$fs) . "\n";

if (function_exists('exec')) {
    $out = array();
    @exec('stat -c%s ' . escapeshellarg($file) . ' 2>&1', $out);
    echo "shell `stat -c%s`        = " . (isset($out[0]) ? $out[0] : '(exec indisponible)') . "\n";
}
