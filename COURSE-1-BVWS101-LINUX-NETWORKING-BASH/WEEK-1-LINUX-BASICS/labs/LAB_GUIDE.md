# LAB-1.1.3: Linux CLI Practice - File Navigation & User Permissions

## Lab Overview

**Course:** BVWS101 – Foundations of Linux, Networking & Bash Scripting  
**Lab Code:** LAB-1.1.3  
**Lab Title:** Linux CLI Practice: File Navigation & User Permissions  
**Duration:** 2-3 hours  
**Difficulty:** Beginner  
**Objectives:** Master essential Linux command-line operations, file system navigation, and permission management for web application security testing.

---

## Lab Introduction

Welcome to your first Linux fundamentals lab! As a web application security professional, you'll spend significant time working in Linux environments. This lab builds the foundation for all future security testing activities.

### Learning Objectives

By completing this lab, you will be able to:
- Navigate the Linux file system efficiently using command-line tools
- Create, modify, and delete files and directories
- Understand and manage Linux file permissions
- Apply the principle of least privilege to file access
- Use essential Linux commands for security testing workflows
- Troubleshoot common permission-related issues

---

## Lab Setup

### Prerequisites
- Kali Linux VM or any Linux distribution (Ubuntu, Debian, etc.)
- Terminal access
- Basic understanding of operating system concepts
- No additional software installation required

### Lab Environment
- **OS:** Kali Linux 2024.x or Ubuntu 22.04+
- **User:** Standard user account with sudo privileges
- **Working Directory:** `/home/[username]/fellowship-labs/`

---

## Part 1: Linux File System Navigation (30 minutes)

### Exercise 1.1: Understanding the File System Hierarchy

The Linux file system follows a hierarchical tree structure starting from the root directory `/`.

**Key Directories:**
- `/` - Root directory (top of the hierarchy)
- `/home` - User home directories
- `/etc` - System configuration files
- `/var` - Variable data (logs, databases)
- `/tmp` - Temporary files
- `/usr` - User programs and data
- `/bin` - Essential command binaries
- `/sbin` - System administration binaries

**Task 1:** Explore the file system structure

```bash
# Display the current working directory
pwd

# List contents of root directory
ls /

# List with detailed information
ls -l /

# List including hidden files
ls -la /

# View directory tree (install tree if not available)
sudo apt install tree -y
tree -L 2 /
```

**Question 1.1:** What is the difference between `/bin` and `/usr/bin`? Why do both exist?

**Question 1.2:** Why are system logs stored in `/var/log` instead of `/home`?

---

### Exercise 1.2: Navigating Directories

**Task 2:** Practice directory navigation

```bash
# Create lab working directory
mkdir -p ~/fellowship-labs/week1
cd ~/fellowship-labs/week1

# Verify current location
pwd

# Go to parent directory
cd ..

# Return to previous directory
cd -

# Go to home directory
cd ~
# or simply
cd

# Go to root directory
cd /

# Return to lab directory
cd ~/fellowship-labs/week1
```

**Task 3:** Create a complex directory structure

```bash
# Create nested directories in one command
mkdir -p ~/fellowship-labs/week1/{recon,exploitation,reporting}/{tools,data,results}

# Visualize the structure
tree ~/fellowship-labs/week1

# Navigate through the structure
cd ~/fellowship-labs/week1/recon/tools
pwd

# Go up two levels
cd ../..
pwd

# Use absolute path
cd /home/$USER/fellowship-labs/week1/exploitation/data
pwd
```

**Question 1.3:** What's the difference between absolute and relative paths? When would you use each?

---

### Exercise 1.3: File Operations

**Task 4:** Create and manipulate files

```bash
# Navigate to lab directory
cd ~/fellowship-labs/week1

# Create empty files
touch test1.txt test2.txt test3.txt

# Create file with content using echo
echo "This is a test file for web security lab" > readme.txt

# Append content to file
echo "Created on $(date)" >> readme.txt

# View file contents
cat readme.txt

# View with line numbers
cat -n readme.txt

# View large files page by page
less readme.txt
# Press 'q' to quit

# View first 10 lines
head readme.txt

# View last 10 lines
tail readme.txt

# Copy files
cp readme.txt readme_backup.txt

# Move/rename files
mv test1.txt renamed_test.txt

# Remove files
rm test2.txt

# Remove with confirmation
rm -i test3.txt
```

**Task 5:** Work with multiple files

```bash
# Create multiple files at once
touch file{1..10}.txt

# List them
ls -l file*.txt

# Copy all to a subdirectory
mkdir backup
cp file*.txt backup/

# Verify
ls backup/

# Remove multiple files
rm file{6..10}.txt

# Verify deletion
ls file*.txt
```

**Question 1.4:** Why is it dangerous to use `rm -rf /` as root? What does each flag do?

---

## Part 2: Understanding Linux Permissions (45 minutes)

### Exercise 2.1: Permission Basics

Linux uses a permission system based on three categories:
- **Owner (u):** The user who owns the file
- **Group (g):** Users in the file's group
- **Others (o):** All other users

Each category has three permissions:
- **Read (r):** View file contents or list directory contents
- **Write (w):** Modify file or create/delete files in directory
- **Execute (x):** Run file as program or enter directory

**Task 6:** Examine file permissions

```bash
cd ~/fellowship-labs/week1

# Create a test file
echo "Security test file" > permissions_test.txt

# View permissions
ls -l permissions_test.txt

# Output explanation:
# -rw-rw-r-- 1 user group 20 Nov 19 10:00 permissions_test.txt
# │││││││││
# ││││││││└─ Other permissions (r--)
# │││││││└── Group permissions (rw-)
# ││││││└─── Owner permissions (rw-)
# │││││└──── Number of hard links
# ││││└───── Owner name
# │││└────── Group name
# ││└─────── File size
# │└──────── Last modified date/time
# └───────── File type (- = regular file, d = directory, l = link)
```

**Permission Notation:**
- **Symbolic:** rwxrwxrwx (read, write, execute for owner, group, others)
- **Numeric (Octal):** 777 (4=read, 2=write, 1=execute)

**Common Permission Values:**
- `644` (rw-r--r--): Owner can read/write, others can only read
- `755` (rwxr-xr-x): Owner can read/write/execute, others can read/execute
- `700` (rwx------): Only owner has all permissions
- `600` (rw-------): Only owner can read/write

---

### Exercise 2.2: Modifying Permissions

**Task 7:** Change file permissions using symbolic notation

```bash
# Create test files
touch script.sh data.txt config.conf

# Make script executable
chmod +x script.sh
ls -l script.sh

# Remove write permission for group and others
chmod go-w data.txt
ls -l data.txt

# Add read permission for everyone
chmod a+r config.conf
ls -l config.conf

# Set specific permissions for each category
chmod u=rwx,g=rx,o=r script.sh
ls -l script.sh
```

**Task 8:** Change permissions using numeric notation

```bash
# Set permissions to 644 (rw-r--r--)
chmod 644 data.txt
ls -l data.txt

# Set permissions to 755 (rwxr-xr-x)
chmod 755 script.sh
ls -l script.sh

# Set permissions to 600 (rw-------)
chmod 600 config.conf
ls -l config.conf

# Dangerous: 777 gives everyone full access
chmod 777 test_file.txt  # AVOID THIS IN PRODUCTION!
ls -l test_file.txt
```

**Security Note:** Never use `chmod 777` on production systems. It allows anyone to read, modify, or execute the file, creating serious security vulnerabilities.

---

### Exercise 2.3: Directory Permissions

Directory permissions work differently:
- **Read (r):** List directory contents
- **Write (w):** Create/delete files in directory
- **Execute (x):** Enter directory (cd into it)

**Task 9:** Understand directory permissions

```bash
# Create test directory
mkdir test_dir
ls -ld test_dir

# Create file inside
echo "test" > test_dir/file.txt

# Remove execute permission from directory
chmod -x test_dir

# Try to enter directory (will fail)
cd test_dir

# Try to list contents (will fail)
ls test_dir

# Restore execute permission
chmod +x test_dir

# Now it works
cd test_dir
pwd
cd ..

# Remove read permission
chmod -r test_dir

# Can enter but can't list contents
cd test_dir
ls
cd ..

# Restore all permissions
chmod 755 test_dir
```

**Question 2.1:** Why does a directory need execute permission to be accessed?

---

### Exercise 2.4: Changing Ownership

**Task 10:** Change file ownership (requires sudo)

```bash
# Create test file
echo "ownership test" > ownership_test.txt

# View current ownership
ls -l ownership_test.txt

# Change owner (requires root)
sudo chown root ownership_test.txt
ls -l ownership_test.txt

# Change back to your user
sudo chown $USER ownership_test.txt
ls -l ownership_test.txt

# Change owner and group together
sudo chown $USER:$USER ownership_test.txt
ls -l ownership_test.txt

# Change only group
sudo chgrp $USER ownership_test.txt
ls -l ownership_test.txt
```

**Question 2.2:** Why do you need sudo to change file ownership?

---

## Part 3: Practical Security Scenarios (45 minutes)

### Exercise 3.1: Securing Web Application Files

**Scenario:** You're deploying a web application and need to set appropriate permissions.

**Task 11:** Set up secure file permissions for a web application

```bash
# Create web application structure
mkdir -p ~/fellowship-labs/week1/webapp/{public,config,logs,uploads}

# Create sample files
echo "<html><body>Home Page</body></html>" > ~/fellowship-labs/week1/webapp/public/index.html
echo "DB_PASSWORD=secret123" > ~/fellowship-labs/week1/webapp/config/database.conf
echo "2024-11-19 10:00:00 - Server started" > ~/fellowship-labs/week1/webapp/logs/app.log
touch ~/fellowship-labs/week1/webapp/uploads/user_upload.jpg

# Set appropriate permissions
cd ~/fellowship-labs/week1/webapp

# Public files: readable by everyone
chmod 644 public/index.html

# Config files: readable only by owner (contains secrets!)
chmod 600 config/database.conf

# Log files: writable by owner, readable by group
chmod 640 logs/app.log

# Upload directory: owner can write, others can read
chmod 755 uploads/
chmod 644 uploads/user_upload.jpg

# Verify permissions
ls -lR
```

**Question 3.1:** Why should configuration files containing passwords have 600 permissions?

**Question 3.2:** What could happen if the uploads directory has 777 permissions?

---

### Exercise 3.2: Finding Files with Insecure Permissions

**Task 12:** Identify security risks in file permissions

```bash
cd ~/fellowship-labs/week1

# Create files with various permissions
touch secure_file.txt insecure_file.txt
chmod 600 secure_file.txt
chmod 777 insecure_file.txt

# Find world-writable files (security risk!)
find ~/fellowship-labs/week1 -type f -perm -002

# Find files with 777 permissions
find ~/fellowship-labs/week1 -type f -perm 0777

# Find SUID files (can be exploited)
sudo find /usr/bin -type f -perm -4000

# Find files owned by root with write permissions for others
sudo find /etc -type f -perm -002 -user root
```

**Security Alert:** World-writable files (permission 2 or 777) are major security risks. Any user can modify them, potentially injecting malicious code.

---

### Exercise 3.3: Special Permissions

**Task 13:** Understand SUID, SGID, and Sticky Bit

```bash
# SUID (Set User ID): File executes with owner's permissions
# Numeric: 4xxx (e.g., 4755)
touch suid_test
chmod 4755 suid_test
ls -l suid_test
# Output: -rwsr-xr-x (note the 's' in owner execute position)

# SGID (Set Group ID): File executes with group's permissions
# Numeric: 2xxx (e.g., 2755)
touch sgid_test
chmod 2755 sgid_test
ls -l sgid_test
# Output: -rwxr-sr-x (note the 's' in group execute position)

# Sticky Bit: Only file owner can delete files in directory
# Numeric: 1xxx (e.g., 1777)
mkdir sticky_dir
chmod 1777 sticky_dir
ls -ld sticky_dir
# Output: drwxrwxrwt (note the 't' at the end)

# Example: /tmp directory uses sticky bit
ls -ld /tmp
```

**Security Implications:**
- **SUID:** Can be exploited for privilege escalation if misconfigured
- **SGID:** Useful for shared directories but can be risky
- **Sticky Bit:** Prevents users from deleting others' files (good for /tmp)

---

## Part 4: Command Line Efficiency (30 minutes)

### Exercise 4.1: Essential Commands for Security Work

**Task 14:** Master commands used in security testing

```bash
cd ~/fellowship-labs/week1

# Search for text in files (useful for finding secrets)
grep -r "password" .
grep -ri "api_key" .  # case-insensitive

# Find files by name
find . -name "*.conf"
find . -name "*.txt"

# Find files modified in last 24 hours
find . -type f -mtime -1

# Find large files (potential data exfiltration)
find . -type f -size +10M

# Count lines in files
wc -l *.txt

# Display disk usage
du -sh *
df -h

# View running processes
ps aux | grep apache
ps aux | grep mysql

# Check network connections
netstat -tuln
ss -tuln

# View system information
uname -a
cat /etc/os-release
```

---

### Exercise 4.2: Command Chaining and Redirection

**Task 15:** Combine commands for efficiency

```bash
# Redirect output to file
ls -la > file_list.txt

# Append to file
date >> file_list.txt

# Redirect errors to file
ls /nonexistent 2> errors.txt

# Redirect both output and errors
ls /nonexistent > output.txt 2>&1

# Pipe commands together
cat /etc/passwd | grep $USER
ps aux | grep apache | wc -l

# Chain commands with && (execute if previous succeeds)
mkdir new_dir && cd new_dir && touch file.txt

# Chain with || (execute if previous fails)
cd /nonexistent || echo "Directory doesn't exist"

# Chain with ; (execute regardless)
echo "First command" ; echo "Second command"
```

---

## Part 5: Lab Challenge (30 minutes)

### Challenge: Secure a Vulnerable System

**Scenario:** You've inherited a web application with poor security practices. Fix the permission issues.

**Task 16:** Complete the security audit and remediation

```bash
# Create the vulnerable system
cd ~/fellowship-labs/week1
mkdir -p challenge/{www,config,scripts,data}

# Create files with insecure permissions
echo "<?php echo 'Hello'; ?>" > challenge/www/index.php
chmod 777 challenge/www/index.php

echo "DB_PASSWORD=admin123" > challenge/config/db.conf
chmod 644 challenge/config/db.conf

echo "#!/bin/bash\nbackup.sh" > challenge/scripts/backup.sh
chmod 666 challenge/scripts/backup.sh

echo "sensitive data" > challenge/data/users.db
chmod 777 challenge/data/users.db

# Your tasks:
# 1. Find all files with 777 permissions
# 2. Find all files with world-readable sensitive data
# 3. Fix permissions according to best practices:
#    - Web files: 644
#    - Config files: 600
#    - Scripts: 700 (executable only by owner)
#    - Data files: 600
# 4. Document your changes
```

**Solution:**

```bash
# 1. Find insecure files
find challenge/ -type f -perm 0777
find challenge/ -type f -perm -004

# 2. Fix permissions
chmod 644 challenge/www/index.php
chmod 600 challenge/config/db.conf
chmod 700 challenge/scripts/backup.sh
chmod 600 challenge/data/users.db

# 3. Verify
ls -lR challenge/

# 4. Create audit report
cat > security_audit_report.txt << EOF
Security Audit Report
Date: $(date)
System: Fellowship Lab Challenge

Issues Found:
1. index.php had 777 permissions (world-writable)
2. db.conf had 644 permissions (world-readable with passwords)
3. backup.sh had 666 permissions (not executable, world-writable)
4. users.db had 777 permissions (world-writable sensitive data)

Remediation Actions:
1. Set index.php to 644 (owner rw, others r)
2. Set db.conf to 600 (owner only)
3. Set backup.sh to 700 (owner only, executable)
4. Set users.db to 600 (owner only)

Verification: All permissions now follow least privilege principle.
EOF

cat security_audit_report.txt
```

---

## Verification and Testing

### Verify Your Learning

**Checklist:**
- [ ] Can navigate the Linux file system using absolute and relative paths
- [ ] Can create, modify, and delete files and directories
- [ ] Understand the meaning of rwx permissions
- [ ] Can change permissions using both symbolic and numeric notation
- [ ] Can identify insecure file permissions
- [ ] Understand the security implications of different permission settings
- [ ] Can use find and grep to locate files and content
- [ ] Can chain commands effectively

**Self-Test Questions:**
1. What permissions does `chmod 755` set?
2. Why is `chmod 777` dangerous?
3. What's the difference between `chown` and `chmod`?
4. How do you find all world-writable files?
5. What does the sticky bit do?

---

## Cleanup

```bash
# Remove lab directory (optional)
rm -rf ~/fellowship-labs/week1

# Or keep for reference
echo "Lab completed on $(date)" > ~/fellowship-labs/week1/completion.txt
```

---

## Submission Requirements

Submit the following:
1. **Screenshots** showing:
   - Your directory structure creation
   - Permission changes before and after
   - Challenge completion with verification
2. **Security Audit Report** from the challenge
3. **Answers** to all questions in this lab
4. **Reflection** (200-300 words) on:
   - Most important concepts learned
   - How file permissions relate to web application security
   - Real-world scenarios where these skills apply

---

## Additional Resources

### Recommended Reading
- [Linux File Permissions Explained](https://www.linux.com/training-tutorials/understanding-linux-file-permissions/)
- [Linux Command Line Basics](https://ubuntu.com/tutorials/command-line-for-beginners)
- [Security Best Practices for Linux](https://www.cyberciti.biz/tips/linux-security.html)

### Practice Platforms
- [OverTheWire: Bandit](https://overthewire.org/wargames/bandit/) - Linux command line game
- [Linux Journey](https://linuxjourney.com/) - Interactive Linux learning

### Cheat Sheets
- [Linux Command Cheat Sheet](https://www.linuxtrainingacademy.com/linux-commands-cheat-sheet/)
- [File Permissions Quick Reference](https://chmod-calculator.com/)

---

## Next Steps

After completing this lab, you'll be ready for:
- **Week 2:** Advanced user and permission management
- **Week 3:** Network fundamentals and security
- **Week 4:** Bash scripting for automation

---

**Lab Version:** 1.0  
**Last Updated:** November 2025  
**Instructor Contact:** resources@aivtic.org.ng

---

## Appendix: Common Commands Reference

```bash
# Navigation
pwd                 # Print working directory
cd <dir>           # Change directory
ls                 # List files
ls -la             # List all files with details

# File Operations
touch <file>       # Create empty file
mkdir <dir>        # Create directory
cp <src> <dst>     # Copy file
mv <src> <dst>     # Move/rename file
rm <file>          # Remove file
rm -rf <dir>       # Remove directory recursively

# Permissions
chmod <mode> <file>     # Change permissions
chown <user> <file>     # Change owner
chgrp <group> <file>    # Change group
ls -l <file>            # View permissions

# Searching
find <dir> -name <pattern>    # Find files
grep <pattern> <file>         # Search in file
grep -r <pattern> <dir>       # Search recursively

# Viewing
cat <file>         # Display file
less <file>        # Page through file
head <file>        # Show first lines
tail <file>        # Show last lines
tail -f <file>     # Follow file updates

# System Info
uname -a           # System information
df -h              # Disk space
du -sh <dir>       # Directory size
ps aux             # Running processes
top                # Process monitor
```

---

**End of Lab Guide**
