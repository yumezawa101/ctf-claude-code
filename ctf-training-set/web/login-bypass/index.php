<?php
// Login Bypass Challenge
// Hint: SQL Injection

$flag = "FLAG{sql_injection_101}";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Vulnerable SQL query
    $query = "SELECT * FROM users WHERE username='$username' AND password='$password'";

    // Simulated check (in real CTF, this would connect to DB)
    if (strpos($username, "'") !== false || strpos($password, "'") !== false) {
        echo "<h2>Welcome Admin!</h2>";
        echo "<p>Flag: $flag</p>";
        exit;
    }
}
?>
<!DOCTYPE html>
<html>
<head><title>Login</title></head>
<body>
    <h1>Login Portal</h1>
    <form method="POST">
        <input type="text" name="username" placeholder="Username"><br>
        <input type="password" name="password" placeholder="Password"><br>
        <button type="submit">Login</button>
    </form>
</body>
</html>
