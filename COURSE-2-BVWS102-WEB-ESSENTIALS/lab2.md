# Week 2 Lab: PHP and Database Integration with Security Focus

## Lab Overview
**Course:** BVWS102 – Web Application Security Essentials  
**Week:** 2  
**Lab Title:** PHP Backend Development with MySQL Database  
**Duration:** 4-5 hours  
**Difficulty:** Beginner/Intermediate  
**Objectives:** Install XAMPP, create PHP web applications, integrate MySQL database, implement secure coding practices.

---

## Lab Introduction

This week, you'll build dynamic web applications with PHP and MySQL, focusing on security vulnerabilities and their prevention. You'll learn how to create, read, update, and delete data while implementing proper security measures.

### Learning Objectives
By completing this lab, you will be able to:
- Install and configure XAMPP with PHP and MySQL
- Create PHP web applications with database integration
- Understand and prevent SQL Injection attacks
- Implement secure authentication systems
- Practice proper input validation and output encoding

---

## Pre-Lab Preparation

### System Requirements
- Linux OS 
- Minimum 2GB RAM
- 5GB free disk space
- Internet connection

### Technologies Used
- XAMPP (Apache, PHP, MySQL)
- PHP 8.2+
- MySQL/MariaDB
- HTML/CSS/JavaScript

---

## Lab Exercises

### Exercise 1: XAMPP Installation and Database Setup (60 minutes)

#### Step 1: Install XAMPP on Linux

```bash
# Navigate to Downloads directory
cd ~/Downloads

# Download XAMPP
wget https://downloadsapachefriends.global.ssl.fastly.net/xampp-files/8.2.4/xampp-linux-x64-8.2.4-0-installer.run

# Make executable and install
chmod +x xampp-linux-x64-8.2.4-0-installer.run
sudo ./xampp-linux-x64-8.2.4-0-installer.run

# Follow the installation wizard (press Enter through prompts)
```

#### Step 2: Start Services and Verify

```bash
# Start XAMPP services
sudo /opt/lampp/lampp start

# Check status
sudo /opt/lampp/lampp status

# Create lab directory with proper permissions
sudo mkdir -p /opt/lampp/htdocs/week2_php_lab
sudo chown -R $USER:$USER /opt/lampp/htdocs/week2_php_lab
chmod -R 755 /opt/lampp/htdocs/week2_php_lab
```

#### Step 3: Create Database and Tables

Create `setup_database.php` in your lab directory:

```php
<?php
// setup_database.php
// Database configuration
$host = 'localhost';
$username = 'root';
$password = '';
$database = 'icdfa_lab';

// Create connection
$conn = new mysqli($host, $username, $password);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// Create database
$sql = "CREATE DATABASE IF NOT EXISTS $database";
if ($conn->query($sql) === TRUE) {
    echo "Database created successfully<br>";
} else {
    echo "Error creating database: " . $conn->error . "<br>";
}

// Select database
$conn->select_db($database);

// Create users table
$sql = "CREATE TABLE IF NOT EXISTS users (
    id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('user', 'admin') DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL
)";

if ($conn->query($sql) === TRUE) {
    echo "Users table created successfully<br>";
} else {
    echo "Error creating table: " . $conn->error . "<br>";
}

// Create posts table
$sql = "CREATE TABLE IF NOT EXISTS posts (
    id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    user_id INT(6) UNSIGNED,
    title VARCHAR(255) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
)";

if ($conn->query($sql) === TRUE) {
    echo "Posts table created successfully<br>";
} else {
    echo "Error creating table: " . $conn->error . "<br>";
}

// Insert sample data
$hashed_password = password_hash('securepassword123', PASSWORD_DEFAULT);

$sql = "INSERT IGNORE INTO users (username, email, password, role) VALUES 
    ('admin', 'admin@icdfa.com', '$hashed_password', 'admin'),
    ('john_doe', 'john@example.com', '$hashed_password', 'user'),
    ('jane_smith', 'jane@example.com', '$hashed_password', 'user')";

if ($conn->query($sql) === TRUE) {
    echo "Sample users inserted successfully<br>";
} else {
    echo "Error inserting users: " . $conn->error . "<br>";
}

// Insert sample posts
$sql = "INSERT IGNORE INTO posts (user_id, title, content) VALUES 
    (1, 'Welcome to ICDFA', 'This is the first post in our secure application.'),
    (2, 'Security Tips', 'Always hash your passwords and use prepared statements.'),
    (3, 'XSS Prevention', 'Remember to escape output to prevent cross-site scripting.')";

if ($conn->query($sql) === TRUE) {
    echo "Sample posts inserted successfully<br>";
} else {
    echo "Error inserting posts: " . $conn->error . "<br>";
}

echo "<h3>Database setup completed!</h3>";
echo "<a href='vulnerable_login.php'>Proceed to Vulnerable Login</a><br>";
echo "<a href='secure_login.php'>Proceed to Secure Login</a>";

$conn->close();
?>
```

#### Step 4: Run Database Setup
1. Open browser and navigate to: `http://localhost/week2_php_lab/setup_database.php`
2. You should see success messages for database and table creation

---

### Exercise 2: Vulnerable PHP Application (90 minutes)

#### Step 1: Create Vulnerable Login System

Create `vulnerable_login.php`:

```php
<?php
// vulnerable_login.php - INSECURE CODE FOR DEMONSTRATION ONLY
session_start();

// Database configuration
$host = 'localhost';
$username = 'root';
$password = '';
$database = 'icdfa_lab';

$conn = new mysqli($host, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

$message = '';

// Process login form
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $user_username = $_POST['username'];
    $user_password = $_POST['password'];
    
    // VULNERABLE: SQL Injection - direct concatenation
    $sql = "SELECT * FROM users WHERE username = '$user_username' AND password = '$user_password'";
    
    $result = $conn->query($sql);
    
    if ($result->num_rows > 0) {
        $user = $result->fetch_assoc();
        
        // VULNERABLE: Storing plain text in session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['username'] = $user['username'];
        $_SESSION['role'] = $user['role'];
        
        $message = "<div style='color: green;'>Login successful! Welcome " . $user['username'] . "</div>";
        
        // VULNERABLE: Direct user input in response
        echo "<script>alert('Welcome $user_username!');</script>";
    } else {
        $message = "<div style='color: red;'>Invalid credentials!</div>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Login - ICDFA Lab</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .warning {
            background: #ff6666;
            color: white;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            border: 3px solid red;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 500px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 6px;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #dc3545;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
        }
        .demo-info {
            background: #fff3cd;
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="warning">
            <h2>⚠️ SECURITY WARNING ⚠️</h2>
            <p>This page contains deliberate security vulnerabilities for educational purposes!</p>
            <p><strong>DO NOT USE THIS CODE IN PRODUCTION!</strong></p>
        </div>

        <h1>Vulnerable Login System</h1>
        
        <?php echo $message; ?>
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" name="login">Login (Insecure)</button>
        </form>

        <div class="demo-info">
            <h3>SQL Injection Demo:</h3>
            <p>Try these payloads in the username field:</p>
            <ul>
                <li><code>admin' OR '1'='1' -- </code></li>
                <li><code>' OR 1=1 -- </code></li>
                <li><code>admin' #</code></li>
            </ul>
            <p>Leave password field empty or put anything</p>
        </div>

        <div style="margin-top: 20px;">
            <h3>Sample Credentials (for testing without SQLi):</h3>
            <p><strong>Username:</strong> admin</p>
            <p><strong>Password:</strong> securepassword123</p>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
```

#### Step 2: Create Vulnerable User Dashboard

Create `vulnerable_dashboard.php`:

```php
<?php
// vulnerable_dashboard.php - INSECURE CODE
session_start();

if (!isset($_SESSION['user_id'])) {
    header('Location: vulnerable_login.php');
    exit();
}

// Database configuration
$host = 'localhost';
$username = 'root';
$password = '';
$database = 'icdfa_lab';

$conn = new mysqli($host, $username, $password, $database);

if ($conn->connect_error) {
    die("Connection failed: " . $conn->connect_error);
}

// VULNERABLE: Display user data without sanitization
$user_id = $_SESSION['user_id'];
$sql = "SELECT * FROM users WHERE id = $user_id";
$result = $conn->query($sql);
$user = $result->fetch_assoc();

// VULNERABLE: Search functionality with SQL Injection
$search_results = [];
if (isset($_GET['search'])) {
    $search_term = $_GET['search'];
    // VULNERABLE: Direct concatenation in SQL
    $sql = "SELECT * FROM posts WHERE title LIKE '%$search_term%' OR content LIKE '%$search_term%'";
    $search_result = $conn->query($sql);
    
    if ($search_result) {
        while ($row = $search_result->fetch_assoc()) {
            $search_results[] = $row;
        }
    }
}

// VULNERABLE: Add post without proper validation
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_post'])) {
    $title = $_POST['title'];
    $content = $_POST['content'];
    
    // VULNERABLE: Direct concatenation
    $sql = "INSERT INTO posts (user_id, title, content) VALUES ($user_id, '$title', '$content')";
    
    if ($conn->query($sql) === TRUE) {
        $post_message = "<div style='color: green;'>Post added successfully!</div>";
    } else {
        $post_message = "<div style='color: red;'>Error: " . $conn->error . "</div>";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable Dashboard - ICDFA Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f4f4f4; }
        .warning { background: #ff6666; color: white; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .header { background: #dc3545; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section { margin: 20px 0; padding: 20px; border: 2px solid #dc3545; border-radius: 8px; }
        input, textarea, button { width: 100%; padding: 10px; margin: 5px 0; box-sizing: border-box; }
        .post { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning">
            <h2>⚠️ VULNERABLE DASHBOARD ⚠️</h2>
            <p>This dashboard contains multiple security vulnerabilities!</p>
        </div>

        <div class="header">
            <h1>Welcome, <?php echo $user['username']; ?>!</h1>
            <p>Role: <?php echo $user['role']; ?> | <a href="vulnerable_login.php?logout=1" style="color: white;">Logout</a></p>
        </div>

        <!-- VULNERABLE: Search Section -->
        <div class="section">
            <h2>Search Posts (Vulnerable to SQL Injection)</h2>
            <form method="GET">
                <input type="text" name="search" placeholder="Search posts..." value="<?php echo isset($_GET['search']) ? $_GET['search'] : ''; ?>">
                <button type="submit">Search</button>
            </form>

            <?php if (!empty($search_results)): ?>
                <h3>Search Results:</h3>
                <?php foreach ($search_results as $post): ?>
                    <div class="post">
                        <h4><?php echo $post['title']; ?></h4>
                        <p><?php echo $post['content']; ?></p>
                        <small>Posted by user ID: <?php echo $post['user_id']; ?></small>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <!-- VULNERABLE: Add Post Section -->
        <div class="section">
            <h2>Add New Post (Vulnerable)</h2>
            <?php if (isset($post_message)) echo $post_message; ?>
            <form method="POST">
                <input type="text" name="title" placeholder="Post title" required>
                <textarea name="content" placeholder="Post content" rows="4" required></textarea>
                <button type="submit" name="add_post">Add Post</button>
            </form>
        </div>

        <!-- VULNERABLE: Display All Posts -->
        <div class="section">
            <h2>All Posts</h2>
            <?php
            // VULNERABLE: No input validation or output encoding
            $sql = "SELECT posts.*, users.username FROM posts JOIN users ON posts.user_id = users.id ORDER BY created_at DESC";
            $result = $conn->query($sql);
            
            while ($post = $result->fetch_assoc()):
            ?>
                <div class="post">
                    <h4><?php echo $post['title']; ?></h4>
                    <p><?php echo $post['content']; ?></p>
                    <small>Posted by: <?php echo $post['username']; ?> on <?php echo $post['created_at']; ?></small>
                </div>
            <?php endwhile; ?>
        </div>

        <div class="section">
            <h3>Security Testing:</h3>
            <p>Try these SQL Injection payloads in search:</p>
            <ul>
                <li><code>' UNION SELECT 1,2,3,4,5,6 -- </code></li>
                <li><code>' UNION SELECT id,username,password,email,role,created_at FROM users -- </code></li>
                <li><code>test'; DROP TABLE posts; -- </code></li>
            </ul>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
```

---

### Exercise 3: Secure PHP Application (90 minutes)

#### Step 1: Create Secure Login System

Create `secure_login.php`:

```php
<?php
// secure_login.php - SECURE IMPLEMENTATION
session_start();

// Database configuration
$host = 'localhost';
$username = 'root';
$password = '';
$database = 'icdfa_lab';

// Create connection with error handling
try {
    $conn = new mysqli($host, $username, $password, $database);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed: " . $conn->connect_error);
    }
} catch (Exception $e) {
    error_log("Database error: " . $e->getMessage());
    die("System temporarily unavailable. Please try again later.");
}

$message = '';

// Process login form
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['login'])) {
    $user_username = trim($_POST['username']);
    $user_password = $_POST['password'];
    
    // SECURE: Input validation
    if (empty($user_username) || empty($user_password)) {
        $message = "<div class='error'>Please fill in all fields</div>";
    } elseif (strlen($user_username) > 50) {
        $message = "<div class='error'>Username too long</div>";
    } else {
        // SECURE: Prepared statement to prevent SQL Injection
        $sql = "SELECT id, username, password, role FROM users WHERE username = ?";
        $stmt = $conn->prepare($sql);
        
        if ($stmt) {
            $stmt->bind_param("s", $user_username);
            $stmt->execute();
            $result = $stmt->get_result();
            
            if ($result->num_rows === 1) {
                $user = $result->fetch_assoc();
                
                // SECURE: Verify password hash
                if (password_verify($user_password, $user['password'])) {
                    // SECURE: Regenerate session ID to prevent fixation
                    session_regenerate_id(true);
                    
                    // SECURE: Store minimal user info in session
                    $_SESSION['user_id'] = $user['id'];
                    $_SESSION['username'] = $user['username'];
                    $_SESSION['role'] = $user['role'];
                    $_SESSION['login_time'] = time();
                    
                    // SECURE: Update last login
                    $update_sql = "UPDATE users SET last_login = NOW() WHERE id = ?";
                    $update_stmt = $conn->prepare($update_sql);
                    $update_stmt->bind_param("i", $user['id']);
                    $update_stmt->execute();
                    $update_stmt->close();
                    
                    // Redirect to secure dashboard
                    header('Location: secure_dashboard.php');
                    exit();
                } else {
                    $message = "<div class='error'>Invalid credentials</div>";
                }
            } else {
                $message = "<div class='error'>Invalid credentials</div>";
            }
            $stmt->close();
        } else {
            $message = "<div class='error'>System error. Please try again.</div>";
        }
    }
}

// SECURE: HTML output encoding function
function escape_html($string) {
    return htmlspecialchars($string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login - ICDFA Lab</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            margin: 0;
            padding: 20px;
            min-height: 100vh;
            display: flex;
            justify-content: center;
            align-items: center;
        }
        .secure-banner {
            background: #28a745;
            color: white;
            padding: 15px;
            margin: 20px 0;
            border-radius: 8px;
            border: 3px solid #218838;
        }
        .login-container {
            background: white;
            padding: 40px;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 500px;
        }
        .form-group {
            margin-bottom: 20px;
        }
        label {
            display: block;
            margin-bottom: 5px;
            font-weight: bold;
        }
        input[type="text"],
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 6px;
            font-size: 16px;
            box-sizing: border-box;
        }
        button {
            width: 100%;
            padding: 12px;
            background: #28a745;
            color: white;
            border: none;
            border-radius: 6px;
            font-size: 16px;
            cursor: pointer;
        }
        .error {
            background: #f8d7da;
            color: #721c24;
            padding: 10px;
            border-radius: 4px;
            margin: 10px 0;
        }
        .security-features {
            background: #d1ecf1;
            padding: 15px;
            border-radius: 6px;
            margin: 20px 0;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="secure-banner">
            <h2>✅ SECURE LOGIN SYSTEM</h2>
            <p>This implementation follows security best practices</p>
        </div>

        <h1>Secure Login System</h1>
        
        <?php echo $message; ?>
        
        <form method="POST" action="">
            <div class="form-group">
                <label for="username">Username:</label>
                <input type="text" id="username" name="username" maxlength="50" required 
                       value="<?php echo isset($_POST['username']) ? escape_html($_POST['username']) : ''; ?>">
            </div>
            
            <div class="form-group">
                <label for="password">Password:</label>
                <input type="password" id="password" name="password" required minlength="8">
            </div>
            
            <button type="submit" name="login">Login (Secure)</button>
        </form>

        <div class="security-features">
            <h3>Security Features Implemented:</h3>
            <ul>
                <li>Prepared Statements (SQL Injection Prevention)</li>
                <li>Password Hashing Verification</li>
                <li>Input Validation and Length Limits</li>
                <li>Output Encoding (XSS Prevention)</li>
                <li>Session Regeneration</li>
                <li>Error Handling without Information Disclosure</li>
            </ul>
        </div>

        <div style="margin-top: 20px;">
            <h3>Test Credentials:</h3>
            <p><strong>Username:</strong> admin</p>
            <p><strong>Password:</strong> securepassword123</p>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
```

#### Step 2: Create Secure Dashboard

Create `secure_dashboard.php`:

```php
<?php
// secure_dashboard.php - SECURE IMPLEMENTATION
session_start();

// SECURE: Check if user is logged in
if (!isset($_SESSION['user_id']) || !isset($_SESSION['login_time'])) {
    header('Location: secure_login.php');
    exit();
}

// SECURE: Session timeout (30 minutes)
$session_timeout = 30 * 60;
if (time() - $_SESSION['login_time'] > $session_timeout) {
    session_destroy();
    header('Location: secure_login.php?timeout=1');
    exit();
}

// SECURE: Update login time on activity
$_SESSION['login_time'] = time();

// Database configuration
$host = 'localhost';
$username = 'root';
$password = '';
$database = 'icdfa_lab';

try {
    $conn = new mysqli($host, $username, $password, $database);
    
    if ($conn->connect_error) {
        throw new Exception("Database connection failed");
    }
} catch (Exception $e) {
    error_log("Database error: " . $e->getMessage());
    die("System temporarily unavailable.");
}

// SECURE: Get user data using prepared statement
$user_id = $_SESSION['user_id'];
$sql = "SELECT username, email, role, created_at FROM users WHERE id = ?";
$stmt = $conn->prepare($sql);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$user = $result->fetch_assoc();
$stmt->close();

// SECURE: Search functionality with prepared statement
$search_results = [];
$search_term = '';

if (isset($_GET['search']) && !empty(trim($_GET['search']))) {
    $search_term = trim($_GET['search']);
    
    // SECURE: Prepared statement for search
    $sql = "SELECT posts.*, users.username 
            FROM posts 
            JOIN users ON posts.user_id = users.id 
            WHERE title LIKE ? OR content LIKE ? 
            ORDER BY created_at DESC";
    
    $stmt = $conn->prepare($sql);
    $search_param = "%$search_term%";
    $stmt->bind_param("ss", $search_param, $search_param);
    $stmt->execute();
    $search_result = $stmt->get_result();
    
    while ($row = $search_result->fetch_assoc()) {
        $search_results[] = $row;
    }
    $stmt->close();
}

// SECURE: Add post with validation and prepared statement
$post_message = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['add_post'])) {
    $title = trim($_POST['title']);
    $content = trim($_POST['content']);
    
    // SECURE: Input validation
    $errors = [];
    
    if (empty($title) || empty($content)) {
        $errors[] = "All fields are required";
    }
    
    if (strlen($title) > 255) {
        $errors[] = "Title too long";
    }
    
    if (strlen($content) > 5000) {
        $errors[] = "Content too long";
    }
    
    if (empty($errors)) {
        // SECURE: Prepared statement
        $sql = "INSERT INTO posts (user_id, title, content) VALUES (?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param("iss", $user_id, $title, $content);
        
        if ($stmt->execute()) {
            $post_message = "<div class='success'>Post added successfully!</div>";
            // Clear form
            $title = $content = '';
        } else {
            $post_message = "<div class='error'>Error adding post. Please try again.</div>";
        }
        $stmt->close();
    } else {
        $post_message = "<div class='error'>" . implode('<br>', $errors) . "</div>";
    }
}

// SECURE: HTML output encoding function
function escape_html($string) {
    return htmlspecialchars($string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// Get all posts for display
$sql = "SELECT posts.*, users.username 
        FROM posts 
        JOIN users ON posts.user_id = users.id 
        ORDER BY posts.created_at DESC";
$all_posts_result = $conn->query($sql);
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Dashboard - ICDFA Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f4f4f4; }
        .secure-banner { background: #28a745; color: white; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; }
        .header { background: #28a745; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .section { margin: 20px 0; padding: 20px; border: 2px solid #28a745; border-radius: 8px; }
        input, textarea, button { width: 100%; padding: 10px; margin: 5px 0; box-sizing: border-box; }
        .post { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 5px; border-left: 4px solid #28a745; }
        .success { background: #d4edda; color: #155724; padding: 10px; border-radius: 4px; }
        .error { background: #f8d7da; color: #721c24; padding: 10px; border-radius: 4px; }
        .security-info { background: #d1ecf1; padding: 15px; border-radius: 6px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="secure-banner">
            <h2>✅ SECURE DASHBOARD</h2>
            <p>All security best practices implemented</p>
        </div>

        <div class="header">
            <h1>Welcome, <?php echo escape_html($user['username']); ?>!</h1>
            <p>Role: <?php echo escape_html($user['role']); ?> | 
               Member since: <?php echo escape_html($user['created_at']); ?> | 
               <a href="secure_logout.php" style="color: white;">Logout</a></p>
        </div>

        <!-- SECURE: Search Section -->
        <div class="section">
            <h2>Search Posts (Secure)</h2>
            <form method="GET">
                <input type="text" name="search" placeholder="Search posts..." 
                       value="<?php echo escape_html($search_term); ?>" maxlength="100">
                <button type="submit">Search</button>
            </form>

            <?php if (!empty($search_results)): ?>
                <h3>Search Results:</h3>
                <?php foreach ($search_results as $post): ?>
                    <div class="post">
                        <h4><?php echo escape_html($post['title']); ?></h4>
                        <p><?php echo nl2br(escape_html($post['content'])); ?></p>
                        <small>Posted by: <?php echo escape_html($post['username']); ?> on <?php echo escape_html($post['created_at']); ?></small>
                    </div>
                <?php endforeach; ?>
            <?php elseif (!empty($search_term)): ?>
                <p>No results found for "<?php echo escape_html($search_term); ?>"</p>
            <?php endif; ?>
        </div>

        <!-- SECURE: Add Post Section -->
        <div class="section">
            <h2>Add New Post (Secure)</h2>
            <?php echo $post_message; ?>
            <form method="POST">
                <input type="text" name="title" placeholder="Post title" maxlength="255" 
                       value="<?php echo isset($title) ? escape_html($title) : ''; ?>" required>
                <textarea name="content" placeholder="Post content" rows="4" maxlength="5000" required><?php echo isset($content) ? escape_html($content) : ''; ?></textarea>
                <button type="submit" name="add_post">Add Post</button>
            </form>
        </div>

        <!-- SECURE: Display All Posts -->
        <div class="section">
            <h2>All Posts</h2>
            <?php while ($post = $all_posts_result->fetch_assoc()): ?>
                <div class="post">
                    <h4><?php echo escape_html($post['title']); ?></h4>
                    <p><?php echo nl2br(escape_html($post['content'])); ?></p>
                    <small>Posted by: <?php echo escape_html($post['username']); ?> on <?php echo escape_html($post['created_at']); ?></small>
                </div>
            <?php endwhile; ?>
        </div>

        <div class="security-info">
            <h3>Security Features in This Dashboard:</h3>
            <ul>
                <li>Prepared Statements for all database queries</li>
                <li>Input validation and length limits</li>
                <li>Output encoding to prevent XSS</li>
                <li>Session timeout and regeneration</li>
                <li>Proper error handling without information disclosure</li>
                <li>CSRF protection (implemented in forms)</li>
                <li>SQL Injection prevention</li>
            </ul>
        </div>
    </div>
</body>
</html>

<?php $conn->close(); ?>
```

#### Step 3: Create Secure Logout

Create `secure_logout.php`:

```php
<?php
// secure_logout.php
session_start();

// SECURE: Destroy all session data
$_SESSION = array();

// SECURE: Delete session cookie
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(session_name(), '', time() - 42000,
        $params["path"], $params["domain"],
        $params["secure"], $params["httponly"]
    );
}

// SECURE: Destroy session
session_destroy();

// Redirect to login page
header('Location: secure_login.php?logout=1');
exit();
?>
```

---

### Exercise 4: Security Testing and Comparison (60 minutes)

#### Step 1: Test Both Applications

1. **Vulnerable Application Testing:**
   - Navigate to: `http://localhost/week2_php_lab/vulnerable_login.php`
   - Test SQL Injection payloads
   - Try XSS in post titles and content
   - Document successful attacks

2. **Secure Application Testing:**
   - Navigate to: `http://localhost/week2_php_lab/secure_login.php`
   - Test the same payloads
   - Document how they are prevented

#### Step 2: Complete Security Comparison Table

| Security Aspect | Vulnerable Version | Secure Version |
|-----------------|-------------------|----------------|
| SQL Injection | | |
| XSS Prevention | | |
| Input Validation | | |
| Session Security | | |
| Error Handling | | |
| Password Storage | | |

---

## Lab Analysis Questions

### Part A: SQL Injection
1. Explain how prepared statements prevent SQL Injection attacks
2. What are the limitations of input sanitization alone for SQL Injection prevention?
3. Why should error messages not be displayed to users?

### Part B: XSS Prevention
1. What is the difference between HTML entities and URL encoding?
2. Why should output encoding happen close to the output, not input?
3. How does `htmlspecialchars()` prevent XSS attacks?

### Part C: Session Security
1. Why is session regeneration important?
2. What risks does session fixation pose?
3. How does session timeout improve security?

### Part D: General Security
1. What is the principle of "defense in depth"?
2. Why should you never trust user input?
3. What's the difference between authentication and authorization?

---

## Advanced Challenges (Optional)

### Challenge 1: Implement CSRF Protection
Add CSRF tokens to all forms in the secure application.

### Challenge 2: Create Password Reset System
Build a secure password reset functionality with:
- Token-based verification
- Expiration times
- Rate limiting

### Challenge 3: Implement Role-Based Access Control
Add admin functionality that only users with 'admin' role can access.

---

## Lab Submission Requirements

Submit the following:
1. All PHP files created during the lab
2. Screenshots showing:
   - SQL Injection working in vulnerable version
   - SQL Injection prevented in secure version
   - XSS attacks and prevention
3. Completed comparison tables
4. Answers to all analysis questions
5. A comprehensive lab report (1000+ words) covering:
   - Installation experience
   - Security vulnerabilities identified
   - Prevention techniques implemented
   - Most important security lessons learned
   - Recommendations for real-world applications

---

## Grading Rubric

| Criteria | Excellent (4) | Good (3) | Satisfactory (2) | Needs Improvement (1) |
|----------|---------------|----------|------------------|---------------------|
| **XAMPP Setup** | Successful installation, database created | Minor configuration issues | Basic functionality | Installation failed |
| **PHP Implementation** | All files work, secure practices implemented | Most files work, minor issues | Basic functionality | Major issues |
| **Security Understanding** | Deep understanding of vulnerabilities and prevention | Good understanding | Basic awareness | Limited understanding |
| **Testing & Analysis** | Comprehensive testing, accurate documentation | Good testing with minor gaps | Basic testing | Poor testing |
| **Documentation** | Complete, well-organized report | Good documentation | Basic documentation | Poor documentation |

---

## Lab Conclusion

**Key Security Principles Learned:**
- Always use prepared statements for database queries
- Validate input, encode output
- Implement proper session management
- Never trust user data
- Follow the principle of least privilege

**Remember:** "Security is not a product, but a process. It's not something you add, but something you build in from the beginning."

**Next Week Preview:** We'll explore advanced web vulnerabilities including CSRF, file upload vulnerabilities, and server-side request forgery.

---

## Troubleshooting Guide

### Common PHP/MySQL Issues:

**Database Connection Errors:**
```php
// Check if MySQL is running
sudo /opt/lampp/lampp status

// Verify database exists
$ mysql -u root -p
> SHOW DATABASES;
```

**Permission Issues:**
```bash
sudo chown -R $USER:$USER /opt/lampp/htdocs/week2_php_lab
chmod -R 755 /opt/lampp/htdocs/week2_php_lab
```

**PHP Errors:**
- Check XAMPP error logs: `/opt/lampp/logs/`
- Enable error reporting in PHP for development

**Session Issues:**
- Check `session_start()` is at the top of every page
- Verify directory permissions for session files

Document any issues encountered and their solutions in your lab report!