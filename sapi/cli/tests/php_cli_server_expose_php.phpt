--TEST--
CLI server respects expose_php=0 on error responses
--SKIPIF--
<?php
include "skipif.inc";
?>
--FILE--
<?php
include "php_cli_server.inc";
// Start server with no router and expose_php=0
php_cli_server_start(null, null, ['-d', 'expose_php=0']);

$fp = php_cli_server_connect();

// Request a non-existent file to trigger a 404 error page response
fwrite($fp, "GET /nonexistent_file.html HTTP/1.1\r\nHost: " . PHP_CLI_SERVER_HOSTNAME . "\r\nConnection: close\r\n\r\n");

$response = '';
while (!feof($fp)) {
    $response .= fgets($fp);
}
fclose($fp);

// Check if X-Powered-By is absent
if (stripos($response, 'X-Powered-By') === false) {
    echo "X-Powered-By not found (PASS)\n";
} else {
    echo "X-Powered-By found (FAIL)\n";
}

// Ensure it was a 404 response
if (strpos($response, '404 Not Found') !== false) {
    echo "404 Not Found (PASS)\n";
} else {
    echo "Expected 404 Not Found (FAIL)\n";
}
?>
--EXPECT--
X-Powered-By not found (PASS)
404 Not Found (PASS)
