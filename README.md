CVE-2024-31214 - WordPress XSS to RCE

Vulnerability Details

· Type: Cross-Site Scripting to Remote Code Execution
· Component: WordPress Core
· CVSS Score: 8.1 High

POC Exploit Chain

Setup Instructions for Lab Testing

1. Create Vulnerable WordPress Environment

```bash
# Using Docker
docker run --name vulnerable-wp -p 8080:80 -e WORDPRESS_DB_HOST=db \
-e WORDPRESS_DB_USER=wpuser -e WORDPRESS_DB_PASSWORD=wppass \
-e WORDPRESS_DB_NAME=wordpress -d wordpress:6.4.0

# Or install manually on Ubuntu
sudo apt update
sudo apt install apache2 php mysql-server
wget https://wordpress.org/wordpress-6.4.0.zip
unzip wordpress-6.4.0.zip
sudo mv wordpress /var/www/html/
```

2. Test the Exploits

```bash
# Run the scanner first
python3 wp-scanner.py http://localhost:8080

# Test specific CVE
python3 cve-2024-27956.py http://localhost:8080
```

3. Detection & Monitoring

Create this detection script for the WordPress server:

```php
<?php
// wp-security-monitor.php
// Place in WordPress root directory
add_action('init', function() {
    $suspicious_patterns = [
        "/UNION.*SELECT/i",
        "/1' AND '1'='1/i",
        "/wp-config.php/i"
    ];
    
    foreach($suspicious_patterns as $pattern) {
        if(preg_match($pattern, $_SERVER['REQUEST_URI'] . print_r($_POST, true) . print_r($_GET, true))) {
            error_log("SUSPICIOUS ACTIVITY: " . $_SERVER['REMOTE_ADDR']);
            file_put_contents('security.log', date('Y-m-d H:i:s') . " - Attack detected from " . $_SERVER['REMOTE_ADDR'] . "\n", FILE_APPEND);
        }
    }
});
```

Important Security Notes

1. Legal Use Only: Test only on systems you own
2. Lab Isolation: Use isolated virtual networks
3. Backup First: Take VM snapshots before testing
4. Update After: Patch vulnerabilities after testing

These exploits target real WordPress vulnerabilities that have been recently discovered. Remember to use them responsibly only in your own lab environment for educational purposes.
