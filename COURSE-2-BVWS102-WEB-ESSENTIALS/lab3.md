# Week 3 Lab: Common Components & Vulnerability Exploration

## Lab Overview
**Course:** BVWS102 – Web Application Security Essentials  
**Week:** 3  
**Lab Title:** Security Analysis & Component Vulnerability Assessment  
**Duration:** 4-5 hours  
**Difficulty:** Intermediate  
**Objectives:** Extend Week 2 application, implement common web components, identify advanced vulnerabilities, practice exploitation and defense.

---

## Lab Introduction

Building on your secure application from Week 2, you'll now implement common web application components while identifying and mitigating advanced security vulnerabilities. You'll learn to think like both a developer and an attacker.

### Learning Objectives
By completing this lab, you will be able to:
- Implement and secure common web components (file uploads, user profiles, comments)
- Identify CSRF, File Upload, and Business Logic vulnerabilities
- Conduct security testing methodology
- Implement advanced security headers and protections
- Practice secure code review techniques

---

## Pre-Lab Setup

### Environment Verification
Ensure your Week 2 environment is running:
```bash
# Start XAMPP services
sudo /opt/lampp/lampp start

# Verify services are running
sudo /opt/lampp/lampp status

# Navigate to your lab directory
cd /opt/lampp/htdocs/week2_php_lab
```

### Database Extension
We'll extend the existing database with new tables for Week 3 features.

---

## Lab Exercises

### Exercise 1: Database Extension & User Profile System (60 minutes)

#### Step 1: Extend Database Schema

Create `extend_database.php`:

```php
<?php
// extend_database.php
session_start();
require_once 'db_config.php';

try {
    // Create user_profiles table
    $sql = "CREATE TABLE IF NOT EXISTS user_profiles (
        id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT(6) UNSIGNED NOT NULL,
        bio TEXT,
        avatar VARCHAR(255),
        website VARCHAR(255),
        location VARCHAR(100),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        UNIQUE KEY unique_user (user_id)
    )";
    
    if ($conn->query($sql) === TRUE) {
        echo "User profiles table created successfully<br>";
    } else {
        throw new Exception("Error creating user_profiles: " . $conn->error);
    }

    // Create file_uploads table
    $sql = "CREATE TABLE IF NOT EXISTS file_uploads (
        id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT(6) UNSIGNED NOT NULL,
        filename VARCHAR(255) NOT NULL,
        original_name VARCHAR(255) NOT NULL,
        file_path VARCHAR(500) NOT NULL,
        file_size INT NOT NULL,
        file_type VARCHAR(100) NOT NULL,
        upload_type ENUM('avatar', 'document', 'image') DEFAULT 'document',
        is_public BOOLEAN DEFAULT FALSE,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )";
    
    if ($conn->query($sql) === TRUE) {
        echo "File uploads table created successfully<br>";
    } else {
        throw new Exception("Error creating file_uploads: " . $conn->error);
    }

    // Create comments table
    $sql = "CREATE TABLE IF NOT EXISTS comments (
        id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        post_id INT(6) UNSIGNED NOT NULL,
        user_id INT(6) UNSIGNED NOT NULL,
        content TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (post_id) REFERENCES posts(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )";
    
    if ($conn->query($sql) === TRUE) {
        echo "Comments table created successfully<br>";
    } else {
        throw new Exception("Error creating comments: " . $conn->error);
    }

    // Create user_sessions table for enhanced security
    $sql = "CREATE TABLE IF NOT EXISTS user_sessions (
        id INT(6) UNSIGNED AUTO_INCREMENT PRIMARY KEY,
        user_id INT(6) UNSIGNED NOT NULL,
        session_id VARCHAR(128) NOT NULL,
        ip_address VARCHAR(45),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_activity TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        is_active BOOLEAN DEFAULT TRUE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
        INDEX session_index (session_id)
    )";
    
    if ($conn->query($sql) === TRUE) {
        echo "User sessions table created successfully<br>";
    } else {
        throw new Exception("Error creating user_sessions: " . $conn->error);
    }

    echo "<h3 style='color: green;'>Database extension completed successfully!</h3>";
    echo "<a href='advanced_dashboard.php'>Proceed to Advanced Dashboard</a>";

} catch (Exception $e) {
    echo "<h3 style='color: red;'>Error: " . $e->getMessage() . "</h3>";
}

$conn->close();
?>
```

#### Step 2: Create Centralized Database Configuration

Create `db_config.php`:

```php
<?php
// db_config.php - Secure database configuration
class DatabaseConfig {
    private $host = 'localhost';
    private $username = 'root';
    private $password = '';
    private $database = 'icdfa_lab';
    private $charset = 'utf8mb4';
    
    public function getConnection() {
        try {
            $dsn = "mysql:host={$this->host};dbname={$this->database};charset={$this->charset}";
            $pdo = new PDO($dsn, $this->username, $this->password);
            $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            $pdo->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
            return $pdo;
        } catch (PDOException $e) {
            error_log("Database connection failed: " . $e->getMessage());
            throw new Exception("Database connection error. Please try again later.");
        }
    }
}

// Create global connection instance
try {
    $dbConfig = new DatabaseConfig();
    $conn = $dbConfig->getConnection();
} catch (Exception $e) {
    die("System temporarily unavailable.");
}
?>
```

#### Step 3: Create Advanced User Profile System

Create `user_profile.php`:

```php
<?php
// user_profile.php - Secure user profile management
session_start();
require_once 'db_config.php';
require_once 'security_functions.php';

if (!isset($_SESSION['user_id']) || !isset($_SESSION['login_time'])) {
    header('Location: secure_login.php');
    exit();
}

// Check session timeout
checkSessionTimeout();

$user_id = $_SESSION['user_id'];
$message = '';

// Handle profile updates
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_profile'])) {
    $bio = trim($_POST['bio']);
    $website = trim($_POST['website']);
    $location = trim($_POST['location']);
    
    // Input validation
    $errors = [];
    
    if (strlen($bio) > 1000) {
        $errors[] = "Bio is too long (max 1000 characters)";
    }
    
    if (!empty($website) && !filter_var($website, FILTER_VALIDATE_URL)) {
        $errors[] = "Please enter a valid website URL";
    }
    
    if (strlen($location) > 100) {
        $errors[] = "Location is too long";
    }
    
    if (empty($errors)) {
        try {
            // Check if profile exists
            $check_sql = "SELECT id FROM user_profiles WHERE user_id = ?";
            $check_stmt = $conn->prepare($check_sql);
            $check_stmt->execute([$user_id]);
            
            if ($check_stmt->rowCount() > 0) {
                // Update existing profile
                $sql = "UPDATE user_profiles SET bio = ?, website = ?, location = ?, updated_at = NOW() WHERE user_id = ?";
            } else {
                // Insert new profile
                $sql = "INSERT INTO user_profiles (user_id, bio, website, location) VALUES (?, ?, ?, ?)";
            }
            
            $stmt = $conn->prepare($sql);
            $stmt->execute([$bio, $website, $location, $user_id]);
            
            $message = "<div class='success'>Profile updated successfully!</div>";
            
        } catch (PDOException $e) {
            error_log("Profile update error: " . $e->getMessage());
            $message = "<div class='error'>Error updating profile. Please try again.</div>";
        }
    } else {
        $message = "<div class='error'>" . implode('<br>', $errors) . "</div>";
    }
}

// Get user profile data
try {
    $sql = "SELECT u.username, u.email, u.role, u.created_at, 
                   p.bio, p.website, p.location, p.avatar
            FROM users u 
            LEFT JOIN user_profiles p ON u.id = p.user_id 
            WHERE u.id = ?";
    $stmt = $conn->prepare($sql);
    $stmt->execute([$user_id]);
    $user_data = $stmt->fetch();
    
    if (!$user_data) {
        throw new Exception("User not found");
    }
    
} catch (Exception $e) {
    error_log("Profile data error: " . $e->getMessage());
    $message = "<div class='error'>Error loading profile data.</div>";
    $user_data = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>User Profile - ICDFA Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f4f4f4; }
        .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 5px; font-weight: bold; color: #333; }
        input, textarea, select { width: 100%; padding: 12px; border: 2px solid #ddd; border-radius: 6px; font-size: 16px; box-sizing: border-box; }
        textarea { height: 120px; resize: vertical; }
        button { background: #28a745; color: white; padding: 12px 30px; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
        .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 6px; margin: 20px 0; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 6px; margin: 20px 0; }
        .profile-section { background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0; border-left: 4px solid #28a745; }
        .nav { background: #343a40; padding: 15px; border-radius: 8px; margin-bottom: 20px; }
        .nav a { color: white; text-decoration: none; margin-right: 20px; padding: 8px 16px; border-radius: 4px; }
        .nav a:hover { background: #495057; }
    </style>
</head>
<body>
    <div class="container">
        <div class="nav">
            <a href="advanced_dashboard.php">Dashboard</a>
            <a href="user_profile.php">My Profile</a>
            <a href="file_upload.php">File Upload</a>
            <a href="secure_logout.php">Logout</a>
        </div>

        <div class="header">
            <h1>User Profile Management</h1>
            <p>Manage your personal information and preferences</p>
        </div>

        <?php echo $message; ?>

        <div class="profile-section">
            <h2>Profile Information</h2>
            <form method="POST" action="">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" value="<?php echo escape_html($user_data['username']); ?>" disabled>
                    <small>Username cannot be changed</small>
                </div>

                <div class="form-group">
                    <label for="email">Email:</label>
                    <input type="email" id="email" value="<?php echo escape_html($user_data['email']); ?>" disabled>
                </div>

                <div class="form-group">
                    <label for="bio">Bio:</label>
                    <textarea id="bio" name="bio" placeholder="Tell us about yourself..." maxlength="1000"><?php echo escape_html($user_data['bio'] ?? ''); ?></textarea>
                </div>

                <div class="form-group">
                    <label for="website">Website:</label>
                    <input type="url" id="website" name="website" placeholder="https://example.com" 
                           value="<?php echo escape_html($user_data['website'] ?? ''); ?>" maxlength="255">
                </div>

                <div class="form-group">
                    <label for="location">Location:</label>
                    <input type="text" id="location" name="location" placeholder="City, Country" 
                           value="<?php echo escape_html($user_data['location'] ?? ''); ?>" maxlength="100">
                </div>

                <button type="submit" name="update_profile">Update Profile</button>
            </form>
        </div>

        <div class="profile-section">
            <h3>Account Information</h3>
            <p><strong>Role:</strong> <?php echo escape_html($user_data['role']); ?></p>
            <p><strong>Member Since:</strong> <?php echo escape_html($user_data['created_at']); ?></p>
            <p><strong>Last Login:</strong> <?php echo isset($_SESSION['last_login']) ? escape_html($_SESSION['last_login']) : 'First login'; ?></p>
        </div>

        <div class="profile-section">
            <h3>Security Features Implemented:</h3>
            <ul>
                <li>Input validation and length limits</li>
                <li>Output encoding to prevent XSS</li>
                <li>SQL Injection prevention with prepared statements</li>
                <li>Session timeout protection</li>
                <li>Secure error handling</li>
                <li>URL validation for website field</li>
            </ul>
        </div>
    </div>
</body>
</html>
```

#### Step 4: Create Security Functions File

Create `security_functions.php`:

```php
<?php
// security_functions.php - Reusable security functions

// HTML output encoding
function escape_html($string) {
    return htmlspecialchars($string, ENT_QUOTES | ENT_HTML5, 'UTF-8');
}

// Check session timeout (30 minutes)
function checkSessionTimeout() {
    $session_timeout = 30 * 60;
    if (time() - $_SESSION['login_time'] > $session_timeout) {
        session_destroy();
        header('Location: secure_login.php?timeout=1');
        exit();
    }
    // Update activity time
    $_SESSION['login_time'] = time();
}

// Generate CSRF token
function generateCSRFToken() {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

// Validate CSRF token
function validateCSRFToken($token) {
    return isset($_SESSION['csrf_token']) && hash_equals($_SESSION['csrf_token'], $token);
}

// Sanitize filename
function sanitizeFilename($filename) {
    // Remove path traversal characters
    $filename = basename($filename);
    // Replace spaces and special characters
    $filename = preg_replace('/[^a-zA-Z0-9\._-]/', '_', $filename);
    // Limit length
    $filename = substr($filename, 0, 100);
    return $filename;
}

// Validate file type
function validateFileType($file_path, $allowed_types) {
    $finfo = finfo_open(FILEINFO_MIME_TYPE);
    $mime_type = finfo_file($finfo, $file_path);
    finfo_close($finfo);
    
    return in_array($mime_type, $allowed_types);
}

// Log security event
function logSecurityEvent($event, $user_id = null, $details = '') {
    $log_entry = date('Y-m-d H:i:s') . " | User: " . ($user_id ?? 'unknown') . " | Event: " . $event . " | Details: " . $details . PHP_EOL;
    file_put_contents('/opt/lampp/htdocs/week2_php_lab/security.log', $log_entry, FILE_APPEND | LOCK_EX);
}
?>
```

---

### Exercise 2: Vulnerable File Upload System (75 minutes)

#### Step 1: Create Vulnerable File Upload Page

Create `vulnerable_upload.php`:

```php
<?php
// vulnerable_upload.php - INSECURE FILE UPLOAD - FOR DEMONSTRATION ONLY
session_start();
require_once 'db_config.php';

if (!isset($_SESSION['user_id'])) {
    header('Location: secure_login.php');
    exit();
}

$user_id = $_SESSION['user_id'];
$message = '';

// VULNERABLE: File upload handling
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['user_file'])) {
    $upload_dir = '/opt/lampp/htdocs/week2_php_lab/uploads/';
    
    // VULNERABLE: No proper validation
    $file_name = $_FILES['user_file']['name'];
    $file_tmp = $_FILES['user_file']['tmp_name'];
    $file_size = $_FILES['user_file']['size'];
    
    // VULNERABLE: Direct use of original filename - Path Traversal risk
    $target_file = $upload_dir . $file_name;
    
    // VULNERABLE: Basic file type check that can be bypassed
    $file_type = strtolower(pathinfo($target_file, PATHINFO_EXTENSION));
    $allowed_types = ['jpg', 'png', 'pdf', 'txt'];
    
    if (in_array($file_type, $allowed_types)) {
        // VULNERABLE: No file content validation
        if (move_uploaded_file($file_tmp, $target_file)) {
            // VULNERABLE: SQL Injection risk
            $sql = "INSERT INTO file_uploads (user_id, filename, original_name, file_path, file_size, file_type) 
                    VALUES ($user_id, '$file_name', '$file_name', '$target_file', $file_size, '$file_type')";
            
            if ($conn->query($sql) === TRUE) {
                $message = "<div style='color: green;'>File uploaded successfully: " . htmlspecialchars($file_name) . "</div>";
            } else {
                $message = "<div style='color: red;'>Database error: " . $conn->error . "</div>";
            }
        } else {
            $message = "<div style='color: red;'>Error uploading file.</div>";
        }
    } else {
        $message = "<div style='color: red;'>Invalid file type. Allowed: " . implode(', ', $allowed_types) . "</div>";
    }
}

// Get user's uploaded files
$sql = "SELECT * FROM file_uploads WHERE user_id = $user_id ORDER BY uploaded_at DESC";
$result = $conn->query($sql);
$user_files = [];
if ($result) {
    $user_files = $result->fetchAll(PDO::FETCH_ASSOC);
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Vulnerable File Upload - ICDFA Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f4f4f4; }
        .warning { background: #ff6666; color: white; padding: 20px; margin: 20px 0; border-radius: 8px; border: 3px solid red; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .upload-area { border: 3px dashed #dc3545; padding: 40px; text-align: center; margin: 20px 0; border-radius: 10px; }
        button { background: #dc3545; color: white; padding: 12px 30px; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
        .file-list { margin-top: 30px; }
        .file-item { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 6px; border-left: 4px solid #dc3545; }
        .exploit-guide { background: #fff3cd; padding: 20px; border-radius: 8px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="warning">
            <h2>⚠️ VULNERABLE FILE UPLOAD SYSTEM ⚠️</h2>
            <p>This page contains multiple security vulnerabilities for educational purposes!</p>
            <p><strong>DO NOT USE THIS CODE IN PRODUCTION!</strong></p>
        </div>

        <h1>Vulnerable File Upload</h1>
        
        <?php echo $message; ?>

        <div class="upload-area">
            <h2>Upload a File (Insecure)</h2>
            <form method="POST" enctype="multipart/form-data">
                <input type="file" name="user_file" required>
                <br><br>
                <button type="submit">Upload File</button>
            </form>
        </div>

        <div class="exploit-guide">
            <h3>🚨 Security Testing Guide</h3>
            <p><strong>Try these exploitation techniques:</strong></p>
            
            <h4>1. Path Traversal Attack:</h4>
            <p>Upload a file named: <code>../../../shell.php</code></p>
            <p>This might overwrite critical system files</p>
            
            <h4>2. File Type Bypass:</h4>
            <p>Rename a PHP shell to: <code>shell.jpg.php</code></p>
            <p>Or modify file signature while keeping .php extension</p>
            
            <h4>3. Large File Attack:</h4>
            <p>Upload extremely large files to cause denial of service</p>
            
            <h4>4. SQL Injection via Filename:</h4>
            <p>Use filename: <code>test'; DROP TABLE file_uploads; -- .jpg</code></p>
        </div>

        <div class="file-list">
            <h2>Your Uploaded Files</h2>
            <?php if (empty($user_files)): ?>
                <p>No files uploaded yet.</p>
            <?php else: ?>
                <?php foreach ($user_files as $file): ?>
                    <div class="file-item">
                        <h4><?php echo htmlspecialchars($file['original_name']); ?></h4>
                        <p>Size: <?php echo round($file['file_size'] / 1024, 2); ?> KB</p>
                        <p>Type: <?php echo htmlspecialchars($file['file_type']); ?></p>
                        <p>Uploaded: <?php echo htmlspecialchars($file['uploaded_at']); ?></p>
                        <a href="<?php echo htmlspecialchars($file['file_path']); ?>" target="_blank">View File</a>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
```

#### Step 2: Create Secure File Upload System

Create `secure_upload.php`:

```php
<?php
// secure_upload.php - SECURE FILE UPLOAD IMPLEMENTATION
session_start();
require_once 'db_config.php';
require_once 'security_functions.php';

if (!isset($_SESSION['user_id']) || !isset($_SESSION['login_time'])) {
    header('Location: secure_login.php');
    exit();
}

checkSessionTimeout();

$user_id = $_SESSION['user_id'];
$message = '';

// Secure upload directory configuration
$upload_base_dir = '/opt/lampp/htdocs/week2_php_lab/uploads/';
$user_upload_dir = $upload_base_dir . 'user_' . $user_id . '/';

// Create user-specific directory if it doesn't exist
if (!is_dir($user_upload_dir)) {
    if (!mkdir($user_upload_dir, 0755, true)) {
        die("Error creating upload directory");
    }
}

// Allowed file types with MIME validation
$allowed_types = [
    'jpg' => 'image/jpeg',
    'png' => 'image/png',
    'gif' => 'image/gif',
    'pdf' => 'application/pdf',
    'txt' => 'text/plain'
];

$max_file_size = 5 * 1024 * 1024; // 5MB

// Secure file upload handling
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['user_file'])) {
    $file_name = $_FILES['user_file']['name'];
    $file_tmp = $_FILES['user_file']['tmp_name'];
    $file_size = $_FILES['user_file']['size'];
    $file_error = $_FILES['user_file']['error'];
    
    // Input validation
    $errors = [];
    
    // Check for upload errors
    if ($file_error !== UPLOAD_ERR_OK) {
        $errors[] = "Upload error: " . $file_error;
    }
    
    // Check file size
    if ($file_size > $max_file_size) {
        $errors[] = "File too large. Maximum size: 5MB";
    }
    
    // Sanitize filename
    $safe_filename = sanitizeFilename($file_name);
    $file_extension = strtolower(pathinfo($safe_filename, PATHINFO_EXTENSION));
    
    // Validate file extension
    if (!array_key_exists($file_extension, $allowed_types)) {
        $errors[] = "Invalid file type. Allowed: " . implode(', ', array_keys($allowed_types));
    }
    
    // Generate unique filename to prevent overwrites
    $unique_filename = uniqid() . '_' . $safe_filename;
    $target_file = $user_upload_dir . $unique_filename;
    
    if (empty($errors)) {
        // Validate actual file content
        if (!validateFileType($file_tmp, array_values($allowed_types))) {
            $errors[] = "File type mismatch detected!";
        }
        
        // Check for PHP tags in text files
        if ($file_extension === 'txt') {
            $file_content = file_get_contents($file_tmp);
            if (preg_match('/<\?php|<\?=|<\/script>/i', $file_content)) {
                $errors[] = "File contains potentially dangerous content";
            }
        }
    }
    
    if (empty($errors)) {
        try {
            // Move uploaded file securely
            if (move_uploaded_file($file_tmp, $target_file)) {
                // Set secure permissions
                chmod($target_file, 0644);
                
                // Store file info in database using prepared statement
                $sql = "INSERT INTO file_uploads (user_id, filename, original_name, file_path, file_size, file_type) 
                        VALUES (?, ?, ?, ?, ?, ?)";
                $stmt = $conn->prepare($sql);
                $stmt->execute([$user_id, $unique_filename, $safe_filename, $target_file, $file_size, $file_extension]);
                
                $message = "<div class='success'>File uploaded securely: " . escape_html($safe_filename) . "</div>";
                logSecurityEvent("FILE_UPLOAD", $user_id, "Uploaded: " . $safe_filename);
                
            } else {
                $errors[] = "Error moving uploaded file";
            }
        } catch (PDOException $e) {
            error_log("File upload database error: " . $e->getMessage());
            $errors[] = "Database error. Please try again.";
        }
    }
    
    if (!empty($errors)) {
        $message = "<div class='error'>" . implode('<br>', $errors) . "</div>";
        logSecurityEvent("UPLOAD_BLOCKED", $user_id, "Rejected: " . $file_name . " - Reasons: " . implode(', ', $errors));
    }
}

// Get user's uploaded files securely
try {
    $sql = "SELECT * FROM file_uploads WHERE user_id = ? ORDER BY uploaded_at DESC";
    $stmt = $conn->prepare($sql);
    $stmt->execute([$user_id]);
    $user_files = $stmt->fetchAll();
} catch (PDOException $e) {
    error_log("File retrieval error: " . $e->getMessage());
    $user_files = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure File Upload - ICDFA Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f4f4f4; }
        .secure-banner { background: #28a745; color: white; padding: 20px; margin: 20px 0; border-radius: 8px; border: 3px solid #218838; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .upload-area { border: 3px dashed #28a745; padding: 40px; text-align: center; margin: 20px 0; border-radius: 10px; }
        button { background: #28a745; color: white; padding: 12px 30px; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
        .file-list { margin-top: 30px; }
        .file-item { background: #f8f9fa; padding: 15px; margin: 10px 0; border-radius: 6px; border-left: 4px solid #28a745; }
        .security-features { background: #d1ecf1; padding: 20px; border-radius: 8px; margin: 20px 0; }
        .success { background: #d4edda; color: #155724; padding: 15px; border-radius: 6px; margin: 20px 0; }
        .error { background: #f8d7da; color: #721c24; padding: 15px; border-radius: 6px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="secure-banner">
            <h2>✅ SECURE FILE UPLOAD SYSTEM</h2>
            <p>All security best practices implemented</p>
        </div>

        <h1>Secure File Upload</h1>
        
        <?php echo $message; ?>

        <div class="upload-area">
            <h2>Upload a File (Secure)</h2>
            <form method="POST" enctype="multipart/form-data">
                <input type="file" name="user_file" accept=".jpg,.jpeg,.png,.gif,.pdf,.txt" required>
                <br><br>
                <button type="submit">Upload File Securely</button>
            </form>
            <p><small>Maximum file size: 5MB | Allowed types: JPG, PNG, GIF, PDF, TXT</small></p>
        </div>

        <div class="security-features">
            <h3>🔒 Security Features Implemented:</h3>
            <ul>
                <li><strong>File Type Validation:</strong> Both extension and MIME type checking</li>
                <li><strong>Size Limits:</strong> Maximum 5MB file size</li>
                <li><strong>Filename Sanitization:</strong> Path traversal prevention</li>
                <li><strong>Unique Filenames:</strong> Prevents overwrite attacks</li>
                <li><strong>User Isolation:</strong> Separate directories per user</li>
                <li><strong>Content Checking:</strong> Detects malicious content in text files</li>
                <li><strong>Secure Permissions:</strong> Files stored with 0644 permissions</li>
                <li><strong>Security Logging:</strong> All uploads and blocks are logged</li>
            </ul>
        </div>

        <div class="file-list">
            <h2>Your Uploaded Files</h2>
            <?php if (empty($user_files)): ?>
                <p>No files uploaded yet.</p>
            <?php else: ?>
                <?php foreach ($user_files as $file): ?>
                    <div class="file-item">
                        <h4><?php echo escape_html($file['original_name']); ?></h4>
                        <p>Size: <?php echo round($file['file_size'] / 1024, 2); ?> KB</p>
                        <p>Type: <?php echo escape_html($file['file_type']); ?></p>
                        <p>Uploaded: <?php echo escape_html($file['uploaded_at']); ?></p>
                        <a href="/week2_php_lab/uploads/user_<?php echo $user_id . '/' . escape_html($file['filename']); ?>" target="_blank">View File</a>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
```

---

### Exercise 3: Advanced Dashboard & Comment System (75 minutes)

#### Step 1: Create Advanced Dashboard

Create `advanced_dashboard.php`:

```php
<?php
// advanced_dashboard.php - Enhanced dashboard with multiple components
session_start();
require_once 'db_config.php';
require_once 'security_functions.php';

if (!isset($_SESSION['user_id']) || !isset($_SESSION['login_time'])) {
    header('Location: secure_login.php');
    exit();
}

checkSessionTimeout();

$user_id = $_SESSION['user_id'];
$message = '';

// Get user statistics
try {
    // User stats
    $stats_sql = "SELECT 
        (SELECT COUNT(*) FROM posts WHERE user_id = ?) as post_count,
        (SELECT COUNT(*) FROM file_uploads WHERE user_id = ?) as file_count,
        (SELECT COUNT(*) FROM comments WHERE user_id = ?) as comment_count";
    $stats_stmt = $conn->prepare($stats_sql);
    $stats_stmt->execute([$user_id, $user_id, $user_id]);
    $user_stats = $stats_stmt->fetch();
    
    // Recent activity
    $activity_sql = "(
        SELECT 'post' as type, title as content, created_at 
        FROM posts WHERE user_id = ?
        UNION ALL
        SELECT 'comment' as type, LEFT(content, 50) as content, created_at 
        FROM comments WHERE user_id = ?
        UNION ALL  
        SELECT 'file' as type, original_name as content, uploaded_at as created_at 
        FROM file_uploads WHERE user_id = ?
    ) ORDER BY created_at DESC LIMIT 10";
    $activity_stmt = $conn->prepare($activity_sql);
    $activity_stmt->execute([$user_id, $user_id, $user_id]);
    $recent_activity = $activity_stmt->fetchAll();
    
} catch (PDOException $e) {
    error_log("Dashboard stats error: " . $e->getMessage());
    $user_stats = [];
    $recent_activity = [];
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Advanced Dashboard - ICDFA Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f4f4f4; }
        .container { max-width: 1200px; margin: 0 auto; }
        .header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 40px; border-radius: 15px; margin-bottom: 30px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: white; padding: 25px; border-radius: 10px; text-align: center; box-shadow: 0 2px 10px rgba(0,0,0,0.1); border-top: 4px solid #28a745; }
        .stat-number { font-size: 2.5em; font-weight: bold; color: #28a745; margin: 10px 0; }
        .nav { background: #343a40; padding: 20px; border-radius: 10px; margin-bottom: 30px; display: flex; flex-wrap: wrap; }
        .nav a { color: white; text-decoration: none; margin: 0 15px; padding: 10px 20px; border-radius: 5px; transition: background 0.3s; }
        .nav a:hover { background: #495057; }
        .activity-section { background: white; padding: 25px; border-radius: 10px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        .activity-item { padding: 15px; border-left: 4px solid #007bff; margin: 10px 0; background: #f8f9fa; border-radius: 0 5px 5px 0; }
        .security-tips { background: #d4edda; padding: 20px; border-radius: 10px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>Advanced Security Dashboard</h1>
            <p>Welcome back, <?php echo escape_html($_SESSION['username']); ?>! Here's your security overview.</p>
        </div>

        <div class="nav">
            <a href="advanced_dashboard.php">Dashboard</a>
            <a href="user_profile.php">My Profile</a>
            <a href="secure_upload.php">Secure Upload</a>
            <a href="vulnerable_upload.php">Vulnerable Upload</a>
            <a href="comment_system.php">Comment System</a>
            <a href="security_testing.php">Security Testing</a>
            <a href="secure_logout.php">Logout</a>
        </div>

        <div class="stats-grid">
            <div class="stat-card">
                <h3>Your Posts</h3>
                <div class="stat-number"><?php echo $user_stats['post_count'] ?? 0; ?></div>
                <p>Total published posts</p>
            </div>
            <div class="stat-card">
                <h3>Files Uploaded</h3>
                <div class="stat-number"><?php echo $user_stats['file_count'] ?? 0; ?></div>
                <p>Securely stored files</p>
            </div>
            <div class="stat-card">
                <h3>Comments Made</h3>
                <div class="stat-number"><?php echo $user_stats['comment_count'] ?? 0; ?></div>
                <p>Community interactions</p>
            </div>
            <div class="stat-card">
                <h3>Security Score</h3>
                <div class="stat-number">A+</div>
                <p>All security features active</p>
            </div>
        </div>

        <div class="activity-section">
            <h2>Recent Activity</h2>
            <?php if (empty($recent_activity)): ?>
                <p>No recent activity found.</p>
            <?php else: ?>
                <?php foreach ($recent_activity as $activity): ?>
                    <div class="activity-item">
                        <strong><?php echo ucfirst(escape_html($activity['type'])); ?>:</strong>
                        <?php echo escape_html($activity['content']); ?>
                        <br><small><?php echo escape_html($activity['created_at']); ?></small>
                    </div>
                <?php endforeach; ?>
            <?php endif; ?>
        </div>

        <div class="security-tips">
            <h3>🔒 Security Best Practices Active:</h3>
            <ul>
                <li>✅ Session timeout protection (30 minutes)</li>
                <li>✅ SQL Injection prevention with prepared statements</li>
                <li>✅ XSS protection with output encoding</li>
                <li>✅ Secure file upload validation</li>
                <li>✅ Input validation and sanitization</li>
                <li>✅ Security event logging</li>
                <li>✅ Password hashing with bcrypt</li>
                <li>✅ CSRF protection on all forms</li>
            </ul>
        </div>

        <div class="activity-section">
            <h2>Week 3 Lab Objectives</h2>
            <ol>
                <li>✅ Extend database with new security-focused tables</li>
                <li>✅ Implement secure user profile management</li>
                <li>✅ Create vulnerable vs secure file upload systems</li>
                <li>🔲 Build comment system with XSS protection</li>
                <li>🔲 Implement CSRF protection</li>
                <li>🔲 Conduct comprehensive security testing</li>
                <li>🔲 Analyze and document vulnerabilities</li>
            </ol>
            <p><strong>Next:</strong> Proceed to implement the comment system and CSRF protection.</p>
        </div>
    </div>
</body>
</html>
```

---

### Exercise 4: Security Testing & Vulnerability Analysis (60 minutes)

#### Step 1: Create Security Testing Interface

Create `security_testing.php`:

```php
<?php
// security_testing.php - Security testing and vulnerability analysis
session_start();
require_once 'db_config.php';
require_once 'security_functions.php';

if (!isset($_SESSION['user_id']) || !isset($_SESSION['login_time'])) {
    header('Location: secure_login.php');
    exit();
}

checkSessionTimeout();

if ($_SESSION['role'] !== 'admin') {
    die("Access denied. Admin privileges required.");
}

$test_results = [];

// Run security tests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['run_tests'])) {
    
    // Test 1: SQL Injection Vulnerability Check
    try {
        $test_input = "admin' OR '1'='1";
        $sql = "SELECT * FROM users WHERE username = ?";
        $stmt = $conn->prepare($sql);
        $stmt->execute([$test_input]);
        $result = $stmt->fetch();
        
        $test_results[] = [
            'name' => 'SQL Injection Protection',
            'status' => $result ? 'FAIL' : 'PASS',
            'details' => $result ? 'Vulnerable to SQL Injection' : 'Protected with prepared statements'
        ];
    } catch (Exception $e) {
        $test_results[] = [
            'name' => 'SQL Injection Protection',
            'status' => 'ERROR',
            'details' => 'Test error: ' . $e->getMessage()
        ];
    }

    // Test 2: XSS Vulnerability Check
    $xss_payload = "<script>alert('XSS')</script>";
    $sanitized_output = escape_html($xss_payload);
    
    $test_results[] = [
        'name' => 'XSS Protection',
        'status' => (strpos($sanitized_output, '<script>') === false) ? 'PASS' : 'FAIL',
        'details' => 'Output encoding: ' . $sanitized_output
    ];

    // Test 3: Session Security
    $test_results[] = [
        'name' => 'Session Timeout',
        'status' => (isset($_SESSION['login_time']) && (time() - $_SESSION['login_time']) < (30 * 60)) ? 'PASS' : 'FAIL',
        'details' => 'Session timeout: 30 minutes'
    ];

    // Test 4: File Upload Security
    $upload_dir = '/opt/lampp/htdocs/week2_php_lab/uploads/';
    $test_results[] = [
        'name' => 'Upload Directory Security',
        'status' => is_dir($upload_dir) && is_writable($upload_dir) ? 'PASS' : 'FAIL',
        'details' => 'Upload directory permissions check'
    ];

    // Test 5: CSRF Protection
    $test_results[] = [
        'name' => 'CSRF Token Generation',
        'status' => !empty(generateCSRFToken()) ? 'PASS' : 'FAIL',
        'details' => 'CSRF token system active'
    ];

    logSecurityEvent("SECURITY_TEST_RUN", $_SESSION['user_id'], "Tests executed: " . count($test_results));
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Testing - ICDFA Lab</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background: #f4f4f4; }
        .container { max-width: 1000px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; }
        .test-result { padding: 15px; margin: 10px 0; border-radius: 5px; }
        .pass { background: #d4edda; color: #155724; border-left: 4px solid #28a745; }
        .fail { background: #f8d7da; color: #721c24; border-left: 4px solid #dc3545; }
        .error { background: #fff3cd; color: #856404; border-left: 4px solid #ffc107; }
        button { background: #007bff; color: white; padding: 12px 30px; border: none; border-radius: 6px; font-size: 16px; cursor: pointer; }
        .stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 20px; margin: 20px 0; }
        .stat-card { padding: 20px; text-align: center; border-radius: 8px; color: white; }
        .total { background: #6c757d; }
        .passed { background: #28a745; }
        .failed { background: #dc3545; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Testing Dashboard</h1>
        <p>Run comprehensive security tests on the application components.</p>

        <form method="POST">
            <button type="submit" name="run_tests">Run Security Tests</button>
        </form>

        <?php if (!empty($test_results)): ?>
            <?php
            $total_tests = count($test_results);
            $passed_tests = count(array_filter($test_results, fn($test) => $test['status'] === 'PASS'));
            $failed_tests = $total_tests - $passed_tests;
            ?>
            
            <div class="stats">
                <div class="stat-card total">
                    <h3>Total Tests</h3>
                    <div style="font-size: 2em;"><?php echo $total_tests; ?></div>
                </div>
                <div class="stat-card passed">
                    <h3>Passed</h3>
                    <div style="font-size: 2em;"><?php echo $passed_tests; ?></div>
                </div>
                <div class="stat-card failed">
                    <h3>Failed</h3>
                    <div style="font-size: 2em;"><?php echo $failed_tests; ?></div>
                </div>
            </div>

            <h2>Test Results</h2>
            <?php foreach ($test_results as $test): ?>
                <div class="test-result <?php echo strtolower($test['status']); ?>">
                    <h4><?php echo $test['name']; ?> - <?php echo $test['status']; ?></h4>
                    <p><?php echo $test['details']; ?></p>
                </div>
            <?php endforeach; ?>

            <div style="margin-top: 30px; padding: 20px; background: #e9ecef; border-radius: 8px;">
                <h3>Security Recommendations</h3>
                <?php if ($failed_tests > 0): ?>
                    <p style="color: #dc3545;">⚠️ <strong>Action Required:</strong> Some security tests failed. Review and fix the issues above.</p>
                <?php else: ?>
                    <p style="color: #28a745;">✅ <strong>Excellent:</strong> All security tests passed! Your application is well-protected.</p>
                <?php endif; ?>
                
                <h4>Next Steps for Enhanced Security:</h4>
                <ul>
                    <li>Implement Content Security Policy (CSP) headers</li>
                    <li>Add rate limiting for login attempts</li>
                    <li>Implement two-factor authentication</li>
                    <li>Conduct regular security audits</li>
                    <li>Set up intrusion detection systems</li>
                </ul>
            </div>
        <?php endif; ?>

        <div style="margin-top: 40px; padding: 20px; background: #d1ecf1; border-radius: 8px;">
            <h3>Vulnerability Testing Checklist</h3>
            <form method="POST" action="vulnerability_tests.php">
                <label><input type="checkbox" name="tests[]" value="sql_injection"> SQL Injection Testing</label><br>
                <label><input type="checkbox" name="tests[]" value="xss"> Cross-Site Scripting (XSS)</label><br>
                <label><input type="checkbox" name="tests[]" value="csrf"> CSRF Vulnerability Testing</label><br>
                <label><input type="checkbox" name="tests[]" value="file_upload"> File Upload Security</label><br>
                <label><input type="checkbox" name="tests[]" value="session_security"> Session Management</label><br>
                <label><input type="checkbox" name="tests[]" value="access_control"> Access Control Testing</label><br>
                <button type="submit" style="margin-top: 15px;">Run Selected Tests</button>
            </form>
        </div>
    </div>
</body>
</html>
```

---

## Lab Analysis & Reporting

### Security Testing Assignment

Complete the following security assessment:

#### Part A: Vulnerability Identification
Test both vulnerable and secure versions of each component and document:

| Component | Vulnerability Type | Vulnerable Version Result | Secure Version Result |
|-----------|-------------------|--------------------------|----------------------|
| File Upload | Path Traversal | | |
| File Upload | File Type Bypass | | |
| File Upload | SQL Injection | | |
| User Profile | XSS in Bio Field | | |
| User Profile | SQL Injection | | |
| Comments | XSS Attack | | |
| Sessions | Session Fixation | | |

#### Part B: Security Control Analysis
For each security control implemented, explain:
1. How it prevents specific attacks
2. Potential limitations or bypass methods
3. Additional layers that could be added

#### Part C: Real-World Impact Assessment
Choose three vulnerabilities and describe:
- Real-world consequences if exploited
- Estimated difficulty of exploitation
- Potential business impact

### Advanced Challenges

#### Challenge 1: Implement Content Security Policy
Research and implement CSP headers for the application.

#### Challenge 2: Build Rate Limiting System
Create a rate limiting system for login attempts and file uploads.

#### Challenge 3: Develop Security Monitoring
Build a real-time security monitoring dashboard that alerts on suspicious activities.

---

## Lab Submission Requirements

1. **All PHP files** created during the lab
2. **Security testing reports** with completed tables
3. **Screenshots** of:
   - Successful security tests
   - Blocked attack attempts
   - Security monitoring dashboard
4. **Vulnerability analysis** document (1500+ words) covering:
   - Most critical vulnerabilities found
   - Effectiveness of security controls
   - Recommendations for improvement
   - Lessons learned

5. **Code review** of your own implementation, identifying:
   - Potential security gaps
   - Areas for improvement
   - Best practices implemented

---

## Grading Rubric

| Criteria | Excellent (4) | Good (3) | Satisfactory (2) | Needs Improvement (1) |
|----------|---------------|----------|------------------|---------------------|
| **Implementation** | All components work, security properly implemented | Minor issues in implementation | Basic functionality | Major implementation issues |
| **Security Understanding** | Deep understanding of vulnerabilities and defenses | Good understanding with minor gaps | Basic awareness | Limited understanding |
| **Testing & Analysis** | Comprehensive testing, accurate vulnerability assessment | Good testing coverage | Basic testing performed | Inadequate testing |
| **Documentation** | Excellent documentation with detailed analysis | Good documentation | Basic documentation | Poor documentation |
| **Advanced Features** | All challenges completed with quality implementation | Most challenges completed | Some challenges attempted | No challenges completed |

---

## Lab Conclusion

**Key Security Principles Reinforced:**
- Defense in depth through multiple security layers
- Never trust user input - validate and sanitize everything
- Principle of least privilege for all components
- Comprehensive logging and monitoring
- Regular security testing and assessment

**Remember:** "Security is not a destination, but a continuous journey of improvement and vigilance."

This lab provides a comprehensive foundation in web application security that you can build upon throughout your cybersecurity career. The skills learned here are directly applicable to real-world security assessment and secure development practices.