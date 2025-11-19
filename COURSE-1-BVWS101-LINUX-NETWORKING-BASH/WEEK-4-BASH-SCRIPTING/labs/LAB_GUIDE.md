# LAB-1.4.5: Write Simple Automation Scripts

## Lab Overview

**Course:** BVWS101 – Foundations of Linux, Networking & Bash Scripting  
**Lab Code:** LAB-1.4.5  
**Lab Title:** Write Simple Automation Scripts  
**Duration:** 2-3 hours  
**Difficulty:** Intermediate  
**Objectives:** Master bash scripting fundamentals and create automation scripts for security testing workflows.

---

## Lab Introduction

Bash scripting is essential for automating repetitive security tasks, processing scan results, and building custom tools. This lab teaches you to write practical scripts for web application security testing.

### Learning Objectives

By completing this lab, you will be able to:
- Write bash scripts with proper syntax and structure
- Use variables, conditionals, and loops effectively
- Process command-line arguments and user input
- Automate security testing tasks
- Parse and process log files
- Create reusable security tools
- Implement error handling and logging

---

## Lab Setup

### Prerequisites
- Kali Linux or Ubuntu/Debian system
- Completion of previous Linux labs
- Text editor (vim, nano, or VS Code)
- Basic command-line knowledge

### Lab Environment

```bash
# Create lab directory
mkdir -p ~/fellowship-labs/week4/scripts
cd ~/fellowship-labs/week4/scripts

# Set up text editor
export EDITOR=nano  # or vim, code, etc.
```

---

## Part 1: Bash Scripting Basics (30 minutes)

### Exercise 1.1: Your First Script

**Task 1:** Create a simple hello world script

```bash
#!/bin/bash
# hello.sh - My first bash script

echo "Hello, World!"
echo "Welcome to Bash Scripting"
echo "Today is $(date)"
echo "Current user: $USER"
echo "Home directory: $HOME"
```

**Make it executable and run:**

```bash
chmod +x hello.sh
./hello.sh
```

**Understanding the shebang:**
- `#!/bin/bash` - Tells system to use bash interpreter
- `#!/usr/bin/env bash` - More portable (finds bash in PATH)

---

### Exercise 1.2: Variables

**Task 2:** Work with variables

```bash
#!/bin/bash
# variables.sh - Variable examples

# String variables
name="Security Analyst"
target="192.168.1.100"
tool="nmap"

# Numeric variables
port=80
timeout=30

# Command substitution
current_date=$(date +%Y-%m-%d)
hostname=$(hostname)
ip_address=$(hostname -I | awk '{print $1}')

# Using variables
echo "Name: $name"
echo "Target: $target"
echo "Tool: $tool"
echo "Port: $port"
echo "Date: $current_date"
echo "Hostname: $hostname"
echo "IP: $ip_address"

# Variable operations
echo "Uppercase: ${name^^}"
echo "Lowercase: ${name,,}"
echo "Length: ${#name}"
echo "Substring: ${name:0:8}"

# Read-only variables
readonly CONSTANT="This cannot be changed"
# CONSTANT="New value"  # This would cause an error

# Unsetting variables
unset target
echo "Target after unset: $target"
```

---

### Exercise 1.3: User Input

**Task 3:** Get input from users

```bash
#!/bin/bash
# input.sh - User input examples

# Simple input
echo "Enter your name:"
read name
echo "Hello, $name!"

# Input with prompt
read -p "Enter target IP: " target_ip
echo "Scanning $target_ip..."

# Silent input (for passwords)
read -sp "Enter password: " password
echo ""
echo "Password length: ${#password}"

# Input with timeout
read -t 5 -p "Quick! Enter something (5 seconds): " quick_input
echo "You entered: $quick_input"

# Input with default value
read -p "Enter port [80]: " port
port=${port:-80}
echo "Using port: $port"

# Multiple inputs
read -p "Enter IP and port: " ip port
echo "IP: $ip, Port: $port"
```

---

## Part 2: Control Structures (40 minutes)

### Exercise 2.1: Conditionals (if/else)

**Task 4:** Implement conditional logic

```bash
#!/bin/bash
# conditionals.sh - If/else examples

# Simple if
if [ -f /etc/passwd ]; then
    echo "Password file exists"
fi

# If-else
read -p "Enter a number: " num
if [ $num -gt 10 ]; then
    echo "Number is greater than 10"
else
    echo "Number is 10 or less"
fi

# If-elif-else
read -p "Enter your score: " score
if [ $score -ge 90 ]; then
    echo "Grade: A"
elif [ $score -ge 80 ]; then
    echo "Grade: B"
elif [ $score -ge 70 ]; then
    echo "Grade: C"
elif [ $score -ge 60 ]; then
    echo "Grade: D"
else
    echo "Grade: F"
fi

# File tests
file="/etc/hosts"
if [ -e "$file" ]; then
    echo "File exists"
fi
if [ -f "$file" ]; then
    echo "It's a regular file"
fi
if [ -r "$file" ]; then
    echo "File is readable"
fi
if [ -w "$file" ]; then
    echo "File is writable"
fi
if [ -x "$file" ]; then
    echo "File is executable"
fi

# String comparisons
str1="hello"
str2="world"
if [ "$str1" = "$str2" ]; then
    echo "Strings are equal"
else
    echo "Strings are different"
fi

# Check if string is empty
if [ -z "$str1" ]; then
    echo "String is empty"
else
    echo "String is not empty"
fi

# Numeric comparisons
a=10
b=20
if [ $a -eq $b ]; then echo "Equal"; fi
if [ $a -ne $b ]; then echo "Not equal"; fi
if [ $a -lt $b ]; then echo "$a is less than $b"; fi
if [ $a -le $b ]; then echo "$a is less than or equal to $b"; fi
if [ $a -gt $b ]; then echo "$a is greater than $b"; fi
if [ $a -ge $b ]; then echo "$a is greater than or equal to $b"; fi

# Logical operators
if [ $a -lt 20 ] && [ $b -gt 10 ]; then
    echo "Both conditions are true"
fi

if [ $a -eq 5 ] || [ $b -eq 20 ]; then
    echo "At least one condition is true"
fi

# Case statement
read -p "Enter a command (start/stop/restart): " cmd
case $cmd in
    start)
        echo "Starting service..."
        ;;
    stop)
        echo "Stopping service..."
        ;;
    restart)
        echo "Restarting service..."
        ;;
    *)
        echo "Unknown command"
        ;;
esac
```

---

### Exercise 2.2: Loops

**Task 5:** Implement different loop types

```bash
#!/bin/bash
# loops.sh - Loop examples

# For loop with range
echo "Counting 1 to 5:"
for i in {1..5}; do
    echo "Number: $i"
done

# For loop with list
echo "Scanning ports:"
for port in 80 443 8080 8443; do
    echo "Checking port $port..."
done

# For loop with command output
echo "Files in current directory:"
for file in $(ls); do
    echo "File: $file"
done

# C-style for loop
echo "Even numbers 0-10:"
for ((i=0; i<=10; i+=2)); do
    echo $i
done

# While loop
echo "Countdown:"
count=5
while [ $count -gt 0 ]; do
    echo $count
    count=$((count - 1))
    sleep 1
done
echo "Blast off!"

# Until loop (opposite of while)
counter=1
until [ $counter -gt 5 ]; do
    echo "Counter: $counter"
    counter=$((counter + 1))
done

# Reading file line by line
echo "Reading /etc/passwd:"
while IFS=: read -r username password uid gid comment home shell; do
    echo "User: $username, UID: $uid, Home: $home"
done < /etc/passwd | head -5

# Infinite loop with break
count=0
while true; do
    count=$((count + 1))
    echo "Iteration: $count"
    if [ $count -eq 5 ]; then
        break
    fi
done

# Continue statement
for i in {1..10}; do
    if [ $((i % 2)) -eq 0 ]; then
        continue  # Skip even numbers
    fi
    echo "Odd number: $i"
done
```

---

## Part 3: Functions and Arguments (40 minutes)

### Exercise 3.1: Functions

**Task 6:** Create reusable functions

```bash
#!/bin/bash
# functions.sh - Function examples

# Simple function
greet() {
    echo "Hello from function!"
}

# Call the function
greet

# Function with parameters
greet_user() {
    echo "Hello, $1!"
}

greet_user "Alice"
greet_user "Bob"

# Function with multiple parameters
add_numbers() {
    local num1=$1
    local num2=$2
    local sum=$((num1 + num2))
    echo $sum
}

result=$(add_numbers 10 20)
echo "Sum: $result"

# Function with return value
is_port_open() {
    local host=$1
    local port=$2
    
    if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
        return 0  # Success
    else
        return 1  # Failure
    fi
}

if is_port_open "google.com" 80; then
    echo "Port 80 is open"
else
    echo "Port 80 is closed"
fi

# Function with local variables
calculate() {
    local a=$1
    local b=$2
    local operation=$3
    
    case $operation in
        add)
            echo $((a + b))
            ;;
        subtract)
            echo $((a - b))
            ;;
        multiply)
            echo $((a * b))
            ;;
        divide)
            if [ $b -ne 0 ]; then
                echo $((a / b))
            else
                echo "Error: Division by zero"
                return 1
            fi
            ;;
        *)
            echo "Unknown operation"
            return 1
            ;;
    esac
}

echo "10 + 5 = $(calculate 10 5 add)"
echo "10 - 5 = $(calculate 10 5 subtract)"
echo "10 * 5 = $(calculate 10 5 multiply)"
echo "10 / 5 = $(calculate 10 5 divide)"
```

---

### Exercise 3.2: Command-Line Arguments

**Task 7:** Process script arguments

```bash
#!/bin/bash
# arguments.sh - Command-line argument examples

# Special variables
echo "Script name: $0"
echo "First argument: $1"
echo "Second argument: $2"
echo "All arguments: $@"
echo "Number of arguments: $#"
echo "Process ID: $$"
echo "Last command exit status: $?"

# Check if arguments provided
if [ $# -eq 0 ]; then
    echo "Usage: $0 <arg1> <arg2> ..."
    exit 1
fi

# Process all arguments
echo "Processing arguments:"
for arg in "$@"; do
    echo "  - $arg"
done

# Shift arguments
echo "Original first argument: $1"
shift
echo "After shift, first argument: $1"

# Parse options
while getopts "h:p:v" opt; do
    case $opt in
        h)
            host=$OPTARG
            ;;
        p)
            port=$OPTARG
            ;;
        v)
            verbose=true
            ;;
        \?)
            echo "Invalid option: -$OPTARG"
            exit 1
            ;;
    esac
done

echo "Host: $host"
echo "Port: $port"
echo "Verbose: $verbose"

# Usage: ./arguments.sh -h 192.168.1.1 -p 80 -v
```

---

## Part 4: Practical Security Scripts (60 minutes)

### Exercise 4.1: Port Scanner Script

**Task 8:** Create a simple port scanner

```bash
#!/bin/bash
# port_scanner.sh - Simple TCP port scanner

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to check if port is open
check_port() {
    local host=$1
    local port=$2
    
    if timeout 1 bash -c "cat < /dev/null > /dev/tcp/$host/$port" 2>/dev/null; then
        echo -e "${GREEN}[+]${NC} Port $port is ${GREEN}OPEN${NC}"
        return 0
    else
        echo -e "${RED}[-]${NC} Port $port is ${RED}CLOSED${NC}"
        return 1
    fi
}

# Main script
if [ $# -lt 2 ]; then
    echo "Usage: $0 <host> <start_port> [end_port]"
    echo "Example: $0 192.168.1.1 1 1000"
    exit 1
fi

host=$1
start_port=$2
end_port=${3:-$start_port}

echo -e "${YELLOW}[*]${NC} Scanning $host from port $start_port to $end_port"
echo "----------------------------------------"

open_ports=0
for ((port=start_port; port<=end_port; port++)); do
    if check_port $host $port; then
        ((open_ports++))
    fi
done

echo "----------------------------------------"
echo -e "${YELLOW}[*]${NC} Scan complete. Found $open_ports open ports."
```

---

### Exercise 4.2: Log Analyzer Script

**Task 9:** Parse and analyze log files

```bash
#!/bin/bash
# log_analyzer.sh - Analyze web server logs

logfile="/var/log/apache2/access.log"

if [ ! -f "$logfile" ]; then
    echo "Log file not found: $logfile"
    exit 1
fi

echo "=== Web Server Log Analysis ==="
echo ""

# Total requests
total=$(wc -l < "$logfile")
echo "Total requests: $total"

# Unique IP addresses
unique_ips=$(awk '{print $1}' "$logfile" | sort -u | wc -l)
echo "Unique IP addresses: $unique_ips"

# Top 10 IP addresses
echo ""
echo "Top 10 IP addresses:"
awk '{print $1}' "$logfile" | sort | uniq -c | sort -rn | head -10

# Top 10 requested URLs
echo ""
echo "Top 10 requested URLs:"
awk '{print $7}' "$logfile" | sort | uniq -c | sort -rn | head -10

# HTTP status codes
echo ""
echo "HTTP status codes:"
awk '{print $9}' "$logfile" | sort | uniq -c | sort -rn

# Failed requests (4xx and 5xx)
echo ""
echo "Failed requests:"
awk '$9 ~ /^[45]/ {print $9}' "$logfile" | sort | uniq -c | sort -rn

# Requests by hour
echo ""
echo "Requests by hour:"
awk '{print $4}' "$logfile" | cut -d: -f2 | sort | uniq -c

# Potential SQL injection attempts
echo ""
echo "Potential SQL injection attempts:"
grep -i "union.*select\|concat.*char\|'.*or.*'1'='1" "$logfile" | wc -l

# Potential XSS attempts
echo ""
echo "Potential XSS attempts:"
grep -i "<script\|javascript:\|onerror=" "$logfile" | wc -l

# User agents
echo ""
echo "Top 10 user agents:"
awk -F'"' '{print $6}' "$logfile" | sort | uniq -c | sort -rn | head -10
```

---

### Exercise 4.3: Backup Script

**Task 10:** Create automated backup script

```bash
#!/bin/bash
# backup.sh - Automated backup script

# Configuration
BACKUP_SOURCE="/var/www"
BACKUP_DEST="/backup"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_NAME="webapp_backup_$DATE.tar.gz"
LOG_FILE="/var/log/backup.log"
RETENTION_DAYS=7

# Function to log messages
log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Function to send notification
send_notification() {
    local status=$1
    local message=$2
    # Could integrate with email, Slack, etc.
    log_message "NOTIFICATION: [$status] $message"
}

# Main backup function
perform_backup() {
    log_message "Starting backup of $BACKUP_SOURCE"
    
    # Create backup directory if it doesn't exist
    if [ ! -d "$BACKUP_DEST" ]; then
        mkdir -p "$BACKUP_DEST"
        log_message "Created backup directory: $BACKUP_DEST"
    fi
    
    # Perform backup
    if tar -czf "$BACKUP_DEST/$BACKUP_NAME" "$BACKUP_SOURCE" 2>>"$LOG_FILE"; then
        backup_size=$(du -h "$BACKUP_DEST/$BACKUP_NAME" | cut -f1)
        log_message "Backup completed successfully: $BACKUP_NAME ($backup_size)"
        send_notification "SUCCESS" "Backup completed: $backup_size"
        return 0
    else
        log_message "ERROR: Backup failed"
        send_notification "FAILURE" "Backup failed"
        return 1
    fi
}

# Function to cleanup old backups
cleanup_old_backups() {
    log_message "Cleaning up backups older than $RETENTION_DAYS days"
    
    find "$BACKUP_DEST" -name "webapp_backup_*.tar.gz" -type f -mtime +$RETENTION_DAYS -delete
    
    remaining=$(find "$BACKUP_DEST" -name "webapp_backup_*.tar.gz" -type f | wc -l)
    log_message "Cleanup complete. Remaining backups: $remaining"
}

# Function to verify backup
verify_backup() {
    log_message "Verifying backup integrity"
    
    if tar -tzf "$BACKUP_DEST/$BACKUP_NAME" > /dev/null 2>&1; then
        log_message "Backup verification successful"
        return 0
    else
        log_message "ERROR: Backup verification failed"
        return 1
    fi
}

# Main execution
log_message "========== Backup Script Started =========="

# Check if source exists
if [ ! -d "$BACKUP_SOURCE" ]; then
    log_message "ERROR: Source directory does not exist: $BACKUP_SOURCE"
    exit 1
fi

# Perform backup
if perform_backup; then
    # Verify backup
    verify_backup
    
    # Cleanup old backups
    cleanup_old_backups
    
    log_message "========== Backup Script Completed =========="
    exit 0
else
    log_message "========== Backup Script Failed =========="
    exit 1
fi
```

---

### Exercise 4.4: System Health Check Script

**Task 11:** Monitor system health

```bash
#!/bin/bash
# health_check.sh - System health monitoring

# Thresholds
CPU_THRESHOLD=80
MEM_THRESHOLD=80
DISK_THRESHOLD=80

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Function to check CPU usage
check_cpu() {
    cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    cpu_usage=${cpu_usage%.*}  # Remove decimal
    
    echo -n "CPU Usage: $cpu_usage% "
    if [ $cpu_usage -gt $CPU_THRESHOLD ]; then
        echo -e "${RED}[CRITICAL]${NC}"
        return 1
    else
        echo -e "${GREEN}[OK]${NC}"
        return 0
    fi
}

# Function to check memory usage
check_memory() {
    mem_usage=$(free | grep Mem | awk '{printf("%.0f", $3/$2 * 100)}')
    
    echo -n "Memory Usage: $mem_usage% "
    if [ $mem_usage -gt $MEM_THRESHOLD ]; then
        echo -e "${RED}[CRITICAL]${NC}"
        return 1
    else
        echo -e "${GREEN}[OK]${NC}"
        return 0
    fi
}

# Function to check disk usage
check_disk() {
    disk_usage=$(df -h / | awk 'NR==2 {print $5}' | cut -d'%' -f1)
    
    echo -n "Disk Usage: $disk_usage% "
    if [ $disk_usage -gt $DISK_THRESHOLD ]; then
        echo -e "${RED}[CRITICAL]${NC}"
        return 1
    else
        echo -e "${GREEN}[OK]${NC}"
        return 0
    fi
}

# Function to check services
check_service() {
    local service=$1
    
    if systemctl is-active --quiet $service; then
        echo -e "$service: ${GREEN}[RUNNING]${NC}"
        return 0
    else
        echo -e "$service: ${RED}[STOPPED]${NC}"
        return 1
    fi
}

# Main health check
echo "========== System Health Check =========="
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "Uptime: $(uptime -p)"
echo ""

echo "=== Resource Usage ==="
check_cpu
check_memory
check_disk
echo ""

echo "=== Service Status ==="
check_service apache2
check_service mysql
check_service ssh
echo ""

echo "=== Network Connectivity ==="
if ping -c 1 8.8.8.8 &> /dev/null; then
    echo -e "Internet: ${GREEN}[CONNECTED]${NC}"
else
    echo -e "Internet: ${RED}[DISCONNECTED]${NC}"
fi

echo ""
echo "=== Recent Errors (last 10) ==="
tail -10 /var/log/syslog | grep -i error

echo ""
echo "========================================="
```

---

## Part 5: Lab Challenge (30 minutes)

### Challenge: Build a Web Application Scanner

**Requirements:**

Create a script that:
1. Takes a URL as input
2. Checks if the site is reachable
3. Identifies the web server
4. Scans for common ports (80, 443, 8080, 8443)
5. Checks for common files (robots.txt, sitemap.xml)
6. Tests for common vulnerabilities
7. Generates a report

**Solution Template:**

```bash
#!/bin/bash
# webapp_scanner.sh - Simple web application scanner

# Your code here
```

---

## Verification and Testing

### Checklist

- [ ] Can write basic bash scripts
- [ ] Understand variables and command substitution
- [ ] Can implement conditionals and loops
- [ ] Can create and use functions
- [ ] Can process command-line arguments
- [ ] Can automate security tasks
- [ ] Can parse and process log files
- [ ] Can implement error handling

---

## Cleanup

```bash
# Keep scripts for future use
chmod +x ~/fellowship-labs/week4/scripts/*.sh
echo "Lab completed on $(date)" > ~/fellowship-labs/week4/completion.txt
```

---

## Submission Requirements

Submit:

1. **All scripts created** during the lab
2. **Challenge solution** - Complete web app scanner
3. **Test outputs** - Screenshots of script execution
4. **Reflection** (300-400 words) on bash scripting applications

---

## Additional Resources

- [Bash Scripting Guide](https://www.tldp.org/LDP/abs/html/)
- [ShellCheck](https://www.shellcheck.net/) - Script analysis tool
- [Bash Hackers Wiki](https://wiki.bash-hackers.org/)

---

**Lab Version:** 1.0  
**Last Updated:** November 2025  
**Instructor Contact:** resources@aivtic.org.ng

---

**End of Lab Guide**
