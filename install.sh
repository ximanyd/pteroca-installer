#!/bin/bash

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
PINK='\033[0;35m'
NC='\033[0m' # No Color

# ASCII Art Header
echo -e "${PINK}
 
 
https://pteroca.com
 
 
██████╗ ████████╗███████╗██████╗  ██████╗  ██████╗ █████╗ 
██╔══██╗╚══██╔══╝██╔════╝██╔══██╗██╔═══██╗██╔════╝██╔══██╗
██████╔╝   ██║   █████╗  ██████╔╝██║   ██║██║     ███████║
██╔═══╝    ██║   ██╔══╝  ██╔══██╗██║   ██║██║     ██╔══██║
██║        ██║   ███████╗██║  ██║╚██████╔╝╚██████╗██║  ██║
╚═╝        ╚═╝   ╚══════╝╚═╝  ╚═╝ ╚═════╝  ╚═════╝╚═╝  ╚═╝
 
Unofficial Installation Script
ximanyd | v1.0
${NC}"

# Confirmation prompt
echo -e "\n${PINK}This script will install PteroCA on your system.${NC}"
echo -e "${RED}Warning: This is an unofficial installation script from someone that has no idea what they are doing. Use at your own risk.${NC}"
echo -e "${GREEN}Would you like to proceed with the installation? (y/n): ${NC}"
read -r proceed
if [[ ! $proceed =~ ^[Yy]$ ]]; then
    echo -e "${RED}Installation cancelled by user.${NC}"
    exit 0
fi

# Minimum supported Ubuntu version
MIN_UBUNTU_VERSION="22.04"

# Function to check if the script is run as root
check_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}" >&2
    exit 1
  fi
}

# Function to check the Ubuntu version
check_ubuntu_version() {
  if command -v lsb_release &> /dev/null; then
    UBUNTU_VERSION=$(lsb_release -rs)
  else
    UBUNTU_VERSION=$(grep 'VERSION_ID' /etc/os-release | cut -d '"' -f 2)
  fi

  if ! dpkg --compare-versions "$UBUNTU_VERSION" ge "$MIN_UBUNTU_VERSION"; then
    echo -e "${RED}Error: Unsupported Ubuntu version: $UBUNTU_VERSION. Minimum required version is $MIN_UBUNTU_VERSION.${NC}" >&2
    exit 1
  fi

  echo -e "${GREEN}Ubuntu version $UBUNTU_VERSION is supported.${NC}"
}

# Function to update and upgrade the system
update_and_upgrade() {
    # Prevent interactive prompts during upgrade
    export DEBIAN_FRONTEND=noninteractive
    
    # Update package lists
    echo -e "${GREEN}Updating package lists...${NC}"
    if ! apt-get update -y > /dev/null 2>&1; then
        cleanup_and_exit 1 "Failed to update package lists"
    fi
    
    # Handle package configuration automatically
    echo -e "${GREEN}Upgrading packages...${NC}"
    if ! apt-get \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        upgrade -y > /dev/null 2>&1; then
        cleanup_and_exit 1 "Failed to upgrade packages"
    fi
}

# Function to handle errors and cleanup
cleanup_and_exit() {
    local exit_code=$1
    local error_message=$2
    
    if [ $exit_code -ne 0 ]; then
        echo -e "${RED}Error: $error_message${NC}" >&2
        # Cleanup any partial installation
        [ -d /var/www/pteroca ] && rm -rf /var/www/pteroca
        [ -f /etc/nginx/sites-enabled/pteroca.conf ] && rm -f /etc/nginx/sites-enabled/pteroca.conf
        [ -f /etc/nginx/sites-available/pteroca.conf ] && rm -f /etc/nginx/sites-available/pteroca.conf
    fi
    exit $exit_code
}

# Function to backup existing configurations
backup_existing_configs() {
    local backup_dir="/root/pteroca_backup_$(date +%Y%m%d_%H%M%S)"
    if [ -d /var/www/pteroca ] || [ -f /etc/nginx/sites-available/pteroca.conf ]; then
        echo -e "${GREEN}Creating backup of existing configurations...${NC}"
        mkdir -p "$backup_dir"
        [ -d /var/www/pteroca ] && cp -r /var/www/pteroca "$backup_dir/"
        [ -f /etc/nginx/sites-available/pteroca.conf ] && cp /etc/nginx/sites-available/pteroca.conf "$backup_dir/"
        echo -e "${GREEN}Backup created at: $backup_dir${NC}"
    fi
}

# Function to install required packages
install_required_packages() {
    echo -e "${GREEN}Installing required packages...${NC}"
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        install -y software-properties-common curl apt-transport-https ca-certificates gnupg > /dev/null 2>&1; then
        cleanup_and_exit 1 "Failed to install required packages"
    fi
}

# Function to add PHP repository & update package lists
add_php_repository() {
    export DEBIAN_FRONTEND=noninteractive
    LC_ALL=C.UTF-8 add-apt-repository -y ppa:ondrej/php > /dev/null 2>&1
    apt-get update -y > /dev/null 2>&1
}

# Function to install PHP, MySQL, Nginx, and other required packages
install_php_mysql_nginx() {
    echo -e "${GREEN}Installing PHP, MySQL, Nginx, and dependencies...${NC}"
    export DEBIAN_FRONTEND=noninteractive
    if ! apt-get \
        -o Dpkg::Options::="--force-confdef" \
        -o Dpkg::Options::="--force-confold" \
        install -y php8.2 php8.2-{cli,ctype,iconv,mysql,pdo,mbstring,tokenizer,bcmath,xml,intl,fpm,curl,zip} mysql-server nginx tar unzip git > /dev/null 2>&1; then
        cleanup_and_exit 1 "Failed to install PHP, MySQL, or Nginx"
    fi
    
    # Ensure services are started
    echo -e "${GREEN}Starting required services...${NC}"
    systemctl enable --now mysql nginx php8.2-fpm > /dev/null 2>&1
}

# Function to install Composer
install_composer() {
    if ! command -v composer &> /dev/null; then
        echo -e "${GREEN}Installing Composer...${NC}"
        if ! curl -sS https://getcomposer.org/installer | php -- --install-dir=/usr/local/bin --filename=composer > /dev/null 2>&1; then
            cleanup_and_exit 1 "Failed to install Composer"
        fi
    else
        echo -e "${GREEN}Composer is already installed${NC}"
    fi
}

# Function to setup PteroCA
setup_pteroca() {
    echo -e "${GREEN}Setting up PteroCA...${NC}"
    if [ -d /var/www/pteroca ]; then
        rm -rf /var/www/pteroca
    fi
    mkdir -p /var/www/pteroca && cd /var/www/pteroca
    if ! git clone https://github.com/pteroca-com/panel.git ./ > /dev/null 2>&1; then
        cleanup_and_exit 1 "Failed to clone PteroCA repository"
    fi
    if ! COMPOSER_ALLOW_SUPERUSER=1 composer install --no-dev --optimize-autoloader --no-interaction > /dev/null 2>&1; then
        cleanup_and_exit 1 "Failed to install Composer dependencies"
    fi
}

# Function to patch PHP API library deprecation notices
patch_php_api() {
    echo -e "${GREEN}Patching PHP API library...${NC}"
    
    RESOURCE_FILE="/var/www/pteroca/vendor/timdesm/pterodactyl-php-api/src/Resources/Resource.php"
    COLLECTION_FILE="/var/www/pteroca/vendor/timdesm/pterodactyl-php-api/src/Resources/Collection.php"
    
    # Check if files exist
    if [ ! -f "$RESOURCE_FILE" ]; then
        echo -e "${RED}Error: Original Resource.php file not found${NC}"
        return 1
    fi
    
    if [ ! -f "$COLLECTION_FILE" ]; then
        echo -e "${RED}Error: Original Collection.php file not found${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Creating backups...${NC}"
    # Create backups
    cp "$RESOURCE_FILE" "$RESOURCE_FILE.backup"
    cp "$COLLECTION_FILE" "$COLLECTION_FILE.backup"
    
    if [ ! -f "$RESOURCE_FILE.backup" ] || [ ! -f "$COLLECTION_FILE.backup" ]; then
        echo -e "${RED}Error: Failed to create backup files${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Setting file permissions...${NC}"
    # Ensure we have write permissions
    chmod 644 "$RESOURCE_FILE" "$COLLECTION_FILE"
    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to set file permissions${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Creating temporary files...${NC}"
    # Create temporary files for the new content
    RESOURCE_TMP=$(mktemp)
    COLLECTION_TMP=$(mktemp)
    
    if [ ! -f "$RESOURCE_TMP" ] || [ ! -f "$COLLECTION_TMP" ]; then
        echo -e "${RED}Error: Failed to create temporary files${NC}"
        return 1
    fi
    
    echo -e "${GREEN}Writing new Resource.php content...${NC}"
    # Write the updated Resource.php content
    cat > "$RESOURCE_TMP" << 'EOL'
<?php

namespace Timdesm\PterodactylPhpApi\Resources;

use ArrayAccess;
use JsonSerializable;

#[\AllowDynamicProperties]
class Resource implements ArrayAccess, JsonSerializable
{
    protected $attributes = [];

    public function __construct($attributes = [])
    {
        $this->attributes = $attributes;
    }

    public function __get($key)
    {
        return $this->get($key);
    }

    public function __set($key, $value)
    {
        $this->attributes[$key] = $value;
    }

    public function get($key)
    {
        return $this->attributes[$key] ?? null;
    }

    #[\ReturnTypeWillChange]
    public function offsetExists(mixed $offset): bool
    {
        return isset($this->attributes[$offset]);
    }

    #[\ReturnTypeWillChange]
    public function offsetGet(mixed $offset): mixed
    {
        return $this->get($offset);
    }

    #[\ReturnTypeWillChange]
    public function offsetSet(mixed $offset, mixed $value): void
    {
        $this->attributes[$offset] = $value;
    }

    #[\ReturnTypeWillChange]
    public function offsetUnset(mixed $offset): void
    {
        unset($this->attributes[$offset]);
    }

    #[\ReturnTypeWillChange]
    public function jsonSerialize(): mixed
    {
        return $this->attributes;
    }

    public function __serialize(): array
    {
        return $this->attributes;
    }

    public function __unserialize(array $data): void
    {
        $this->attributes = $data;
    }
}
EOL

    echo -e "${GREEN}Writing new Collection.php content...${NC}"
    # Write the updated Collection.php content
    cat > "$COLLECTION_TMP" << 'EOL'
<?php

namespace Timdesm\PterodactylPhpApi\Resources;

use ArrayAccess;
use Countable;
use JsonSerializable;

#[\AllowDynamicProperties]
class Collection implements ArrayAccess, JsonSerializable, Countable
{
    protected $items = [];

    public function __construct($items = [])
    {
        $this->items = $items;
    }

    #[\ReturnTypeWillChange]
    public function offsetExists(mixed $offset): bool
    {
        return isset($this->items[$offset]);
    }

    #[\ReturnTypeWillChange]
    public function offsetGet(mixed $offset): mixed
    {
        return $this->items[$offset];
    }

    #[\ReturnTypeWillChange]
    public function offsetSet(mixed $offset, mixed $value): void
    {
        if (is_null($offset)) {
            $this->items[] = $value;
        } else {
            $this->items[$offset] = $value;
        }
    }

    #[\ReturnTypeWillChange]
    public function offsetUnset(mixed $offset): void
    {
        unset($this->items[$offset]);
    }

    #[\ReturnTypeWillChange]
    public function jsonSerialize(): mixed
    {
        return $this->items;
    }

    public function count(): int
    {
        return count($this->items);
    }

    public function __serialize(): array
    {
        return $this->items;
    }

    public function __unserialize(array $data): void
    {
        $this->items = $data;
    }

    public function toArray(): array
    {
        return array_map(function ($item) {
            if ($item instanceof Resource) {
                return $item->jsonSerialize();
            }
            return $item;
        }, $this->items);
    }
}
EOL

    if [ $? -ne 0 ]; then
        echo -e "${RED}Error: Failed to write content to temporary files${NC}"
        rm -f "$RESOURCE_TMP" "$COLLECTION_TMP"
        return 1
    fi

    echo -e "${GREEN}Moving temporary files to destination...${NC}"
    # Replace the original files with the new content
    if ! mv "$RESOURCE_TMP" "$RESOURCE_FILE" || ! mv "$COLLECTION_TMP" "$COLLECTION_FILE"; then
        echo -e "${RED}Error: Failed to move temporary files to destination${NC}"
        rm -f "$RESOURCE_TMP" "$COLLECTION_TMP"
        return 1
    fi

    echo -e "${GREEN}Setting final permissions...${NC}"
    # Set proper permissions
    chmod 644 "$RESOURCE_FILE" "$COLLECTION_FILE"
    chown www-data:www-data "$RESOURCE_FILE" "$COLLECTION_FILE"
    
    echo -e "${GREEN}Verifying patches...${NC}"
    # Verify the patches were successful
    if grep -q "#\[\\\ReturnTypeWillChange\]" "$RESOURCE_FILE" && \
       grep -q "#\[\\\ReturnTypeWillChange\]" "$COLLECTION_FILE" && \
       grep -q "mixed \$offset): bool" "$RESOURCE_FILE" && \
       grep -q "mixed \$offset): bool" "$COLLECTION_FILE"; then
        echo -e "${GREEN}Successfully patched PHP API library${NC}"
        rm -f "$RESOURCE_FILE.backup" "$COLLECTION_FILE.backup"
        return 0
    fi
    
    echo -e "${RED}Patch verification failed${NC}"
    echo -e "${RED}Restoring from backups...${NC}"
    # Restore backups if patch failed
    if [ -f "$RESOURCE_FILE.backup" ] && [ -f "$COLLECTION_FILE.backup" ]; then
        mv "$RESOURCE_FILE.backup" "$RESOURCE_FILE"
        mv "$COLLECTION_FILE.backup" "$COLLECTION_FILE"
        echo -e "${GREEN}Restored original files from backup${NC}"
    fi
    return 1
}

# Function to set permissions for PteroCA directories
set_permissions() {
    chown -R www-data:www-data /var/www/pteroca/var/ /var/www/pteroca/public/uploads/ > /dev/null 2>&1
    chmod -R 775 /var/www/pteroca/var/ /var/www/pteroca/public/uploads/ > /dev/null 2>&1
}

# Function to add cron job for PteroCA
add_cron_job() {
    (crontab -l 2>/dev/null; echo "* * * * * php /var/www/pteroca/bin/console app:cron-job-schedule >> /dev/null 2>&1") | crontab - > /dev/null 2>&1
}

# Function to validate FQDN
is_valid_fqdn() {
    local fqdn=$1
    # Strip protocol if present
    fqdn=$(echo "$fqdn" | sed -E 's#^https?://##')
    
    # Check if it's an IP address
    if [[ $fqdn =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 1
    fi
    # Check if it's a valid domain name format (allowing subdomains)
    if [[ $fqdn =~ ^([a-zA-Z0-9][a-zA-Z0-9-]*\.)+[a-zA-Z]{2,}$ ]]; then
        return 0
    fi
    return 1
}

# Function to install and configure Certbot
install_certbot() {
    echo -e "${GREEN}Installing Certbot...${NC}"
    export DEBIAN_FRONTEND=noninteractive
    
    # Install Certbot and Nginx plugin
    if ! apt-get install -y certbot python3-certbot-nginx > /dev/null 2>&1; then
        cleanup_and_exit 1 "Failed to install Certbot"
    fi
}

# Function to obtain SSL certificate
obtain_ssl_certificate() {
    local domain=$1
    echo -e "${GREEN}Obtaining SSL certificate for $domain...${NC}"
    
    # Stop Nginx temporarily to free up port 80
    systemctl stop nginx
    
    # Obtain the certificate
    if ! certbot certonly --standalone --non-interactive --agree-tos --email admin@$domain -d $domain > /dev/null 2>&1; then
        systemctl start nginx
        cleanup_and_exit 1 "Failed to obtain SSL certificate"
    fi
    
    # Setup auto-renewal
    echo -e "${GREEN}Setting up automatic certificate renewal...${NC}"
    (crontab -l 2>/dev/null; echo "0 12 * * * /usr/bin/certbot renew --quiet") | crontab -
}

# Function to configure Nginx with SSL
configure_nginx_ssl() {
    local domain=$1
    cd /etc/nginx/sites-available/

    cat > pteroca.conf <<EOL
server {
    listen 80;
    server_name $domain;
    return 301 https://\$server_name\$request_uri;
}

server {
    listen 443 ssl http2;
    server_name $domain;

    ssl_certificate /etc/letsencrypt/live/$domain/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$domain/privkey.pem;
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:50m;
    ssl_session_tickets off;

    # Modern configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # HSTS (uncomment if you're sure)
    # add_header Strict-Transport-Security "max-age=63072000" always;

    root /var/www/pteroca/public;
    index index.php index.html index.htm;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}
EOL
}

# Function to get FQDN or IP from user
get_fqdn_or_ip() {
    read -p "Enter the domain name for the server (leave blank to use server IP): " FQDN

    if [ -z "$FQDN" ]; then
        SERVERIP=$(hostname -I | awk '{print $1}')
        FQDN=$SERVERIP
        echo -e "${GREEN}No domain provided. Using server IP: $FQDN${NC}"
        USE_SSL=false
    else
        # Strip protocol if present
        FQDN=$(echo "$FQDN" | sed -E 's#^https?://##')
        
        if is_valid_fqdn "$FQDN"; then
            echo -e "${GREEN}Valid domain provided: $FQDN${NC}"
            USE_SSL=true
        else
            echo -e "${RED}Invalid domain format or IP address provided: $FQDN${NC}"
            echo -e "${RED}Please enter a valid domain name (e.g., billing.some.company) or leave blank to use IP address${NC}"
            exit 1
        fi
    fi
}

# Function to configure Nginx for PteroCA with FQDN or IP
configure_nginx_with_fqdn_or_ip() {
    cd /etc/nginx/sites-available/

    # Remove existing configuration if it exists
    if [ -f pteroca.conf ]; then
        rm -f pteroca.conf
    fi

    if [ "$USE_SSL" = true ]; then
        install_certbot
        obtain_ssl_certificate "$FQDN"
        configure_nginx_ssl "$FQDN"
    else
        # Original non-SSL configuration
        cat > pteroca.conf <<EOL
server {
    listen 80;
    root /var/www/pteroca/public;
    index index.php index.html index.htm;
    server_name $FQDN;

    location / {
        try_files \$uri \$uri/ /index.php?\$query_string;
    }

    location ~ \.php\$ {
        include snippets/fastcgi-php.conf;
        fastcgi_pass unix:/var/run/php/php8.2-fpm.sock;
    }

    location ~ /\.ht {
        deny all;
    }
}
EOL
    fi

    # Check if the symbolic link exists and skip adding it if it does
    if [ ! -L /etc/nginx/sites-enabled/pteroca.conf ]; then
        ln -s /etc/nginx/sites-available/pteroca.conf /etc/nginx/sites-enabled/pteroca.conf
    fi
    
    # Remove default nginx site if it exists
    if [ -f /etc/nginx/sites-enabled/default ]; then
        rm -f /etc/nginx/sites-enabled/default
    fi
    
    # Test and reload nginx configuration
    if nginx -t > /dev/null 2>&1; then
        systemctl restart nginx > /dev/null 2>&1
    else
        cleanup_and_exit 1 "Invalid Nginx configuration"
    fi
}

# Function to get database password from user
get_database_password() {
    while true; do
        read -sp "Enter the password you would like to use for the MySQL pterocauser user (minimum 8 characters): " DB_PASS
        echo
        if [ ${#DB_PASS} -lt 8 ]; then
            echo -e "${RED}Password must be at least 8 characters long${NC}"
            continue
        fi
        read -sp "Confirm password: " DB_PASS_CONFIRM
        echo
        if [ "$DB_PASS" != "$DB_PASS_CONFIRM" ]; then
            echo -e "${RED}Passwords do not match${NC}"
            continue
        fi
        break
    done
}

# Function to check and delete existing MySQL database and user
check_and_delete_existing_db_user() {
    DB_EXISTS=$(mysql -u root -e "SHOW DATABASES LIKE 'pteroca';" | grep "pteroca" > /dev/null; echo "$?")
    USER_EXISTS=$(mysql -u root -e "SELECT User FROM mysql.user WHERE User = 'pterocauser';" | grep "pterocauser" > /dev/null; echo "$?")

    if [ "$DB_EXISTS" -eq 0 ]; then
        mysql -u root -e "DROP DATABASE pteroca;" > /dev/null 2>&1
    fi

    if [ "$USER_EXISTS" -eq 0 ]; then
        mysql -u root -e "DROP USER 'pterocauser'@'127.0.0.1';" > /dev/null 2>&1
    fi
}

# Function to setup MySQL database and user
setup_mysql() {
    mysql -u root <<MYSQL_SCRIPT
CREATE DATABASE pteroca;
CREATE USER 'pterocauser'@'127.0.0.1' IDENTIFIED BY '$DB_PASS';
GRANT ALL PRIVILEGES ON pteroca.* TO 'pterocauser'@'127.0.0.1';
FLUSH PRIVILEGES;
MYSQL_SCRIPT
}

# Function to configure PteroCA database
configure_pteroca_database() {
    echo -e "${GREEN}Configuring PteroCA database...${NC}"
    cd /var/www/pteroca
    php bin/console app:configure-database
}

# Function to configure PteroCA system
configure_pteroca_system() {
    echo -e "${GREEN}Configuring PteroCA system...${NC}"
    cd /var/www/pteroca
    php bin/console app:configure-system
}

# Function to check for errors and display completion message
check_for_errors() {
    if [ $? -eq 0 ]; then
        echo -e "\n${GREEN}╔════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║           Installation Complete!           ║${NC}"
        echo -e "${GREEN}╚════════════════════════════════════════════╝${NC}\n"

        echo -e "${GREEN}▣ Installation Details:${NC}"
        echo -e "  ├─ Web Server: Nginx with PHP-FPM 8.2"
        echo -e "  ├─ Database: MySQL (User: pterocauser)"
        echo -e "  ├─ Installation Path: /var/www/pteroca"
        echo -e "  ├─ PHP Version: $(php -v | head -n1)"
        echo -e "  ├─ MySQL Version: $(mysql --version | cut -d' ' -f3-)"
        echo -e "  ├─ Nginx Version: $(nginx -v 2>&1 | cut -d'/' -f2-)"
        if [ "$USE_SSL" = true ]; then
            echo -e "  ├─ SSL: Enabled (Auto-renewal configured)"
            echo -e "  ├─ Certificate Path: /etc/letsencrypt/live/$FQDN/"
            echo -e "  ├─ Certificate Renewal: Daily at 12:00"
        else
            echo -e "  ├─ SSL: Disabled"
        fi
        echo -e "  └─ Cron Job: Configured for automated tasks\n"

        echo -e "${GREEN}▣ Access Information:${NC}"
        if [ "$USE_SSL" = true ]; then
            echo -e "  ├─ Panel URL: https://${FQDN}"
        else
            echo -e "  ├─ Panel URL: http://${FQDN}"
        fi
        echo -e "  ├─ Database Host: 127.0.0.1"
        echo -e "  ├─ Database Name: pteroca"
        echo -e "  └─ Database User: pterocauser\n"

        echo -e "${GREEN}▣ Important Paths:${NC}"
        echo -e "  ├─ Web Root: /var/www/pteroca"
        echo -e "  ├─ Configuration: /var/www/pteroca/.env"
        echo -e "  ├─ Logs: /var/www/pteroca/var/log/"
        echo -e "  ├─ Nginx Config: /etc/nginx/sites-available/pteroca.conf"
        echo -e "  ├─ PHP-FPM Config: /etc/php/8.2/fpm/pool.d/www.conf"
        echo -e "  └─ PHP-FPM Socket: /var/run/php/php8.2-fpm.sock\n"

        echo -e "${GREEN}▣ Service Status:${NC}"
        echo -e "  ├─ Nginx: $(systemctl is-active nginx)"
        echo -e "  ├─ PHP-FPM: $(systemctl is-active php8.2-fpm)"
        echo -e "  └─ MySQL: $(systemctl is-active mysql)\n"

        if [ "$USE_SSL" = true ]; then
            echo -e "${GREEN}▣ SSL Certificate Information:${NC}"
            echo -e "  ├─ Auto-renewal: Configured (daily check at 12:00)"
            echo -e "  ├─ Next Renewal Check: $(certbot certificates 2>/dev/null | grep "VALID:" | cut -d: -f2)"
            echo -e "  └─ Renewal Command: certbot renew\n"
        fi

        echo -e "${GREEN}Thank you for installing PteroCA!${NC}\n"
    else
        echo -e "\n${RED}╔════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║           Installation Failed!             ║${NC}"
        echo -e "${RED}╚════════════════════════════════════════════╝${NC}\n"

        echo -e "${RED}▣ Error Information:${NC}"
        echo -e "  ├─ Last Exit Code: $?"
        echo -e "  ├─ PHP Version: $(php -v 2>&1 | head -n1)"
        echo -e "  ├─ MySQL Status: $(systemctl is-active mysql)"
        echo -e "  └─ Nginx Status: $(systemctl is-active nginx)\n"

        echo -e "${RED}▣ Common Issues:${NC}"
        echo -e "  ├─ Database Connection: Check MySQL credentials and permissions"
        echo -e "  ├─ File Permissions: Ensure proper ownership and access rights"
        echo -e "  ├─ PHP Extensions: Verify all required extensions are installed"
        echo -e "  └─ Web Server: Check Nginx configuration and logs\n"

        echo -e "${RED}▣ Log Files to Check:${NC}"
        echo -e "  ├─ Application Logs: /var/www/pteroca/var/log/*"
        echo -e "  ├─ Nginx Error Log: /var/log/nginx/error.log"
        echo -e "  ├─ PHP-FPM Log: /var/log/php8.2-fpm.log"
        echo -e "  └─ MySQL Error Log: /var/log/mysql/error.log\n"

        echo -e "${RED}▣ Troubleshooting Steps:${NC}"
        echo -e "  ├─ 1. Check log files for specific error messages"
        echo -e "  ├─ 2. Verify all services are running: nginx, php-fpm, mysql"
        echo -e "  ├─ 3. Ensure all required PHP extensions are installed"
        echo -e "  ├─ 4. Check file permissions in /var/www/pteroca"
        echo -e "  ├─ 5. Verify database connection settings"
        echo -e "  └─ 6. Check for system resource limitations\n"

        echo -e "${RED}▣ Quick Fixes:${NC}"
        echo -e "  ├─ Restart Services:"
        echo -e "  │  ├─ systemctl restart nginx"
        echo -e "  │  ├─ systemctl restart php8.2-fpm"
        echo -e "  │  └─ systemctl restart mysql"
        echo -e "  ├─ Fix Permissions:"
        echo -e "  │  └─ chown -R www-data:www-data /var/www/pteroca"
        echo -e "  └─ Clear Cache:"
        echo -e "     └─ php /var/www/pteroca/bin/console cache:clear\n"

        echo -e "${RED}▣ Getting Help:${NC}"
        echo -e "  ├─ Visit: https://pteroca.com/troubleshooting"
        echo -e "  ├─ Forums: https://pteroca.com/community"
        echo -e "  ├─ GitHub: https://github.com/pteroca-com/panel/issues"
        echo -e "  └─ Email: support@pteroca.com\n"

        echo -e "${RED}▣ Debug Information:${NC}"
        echo -e "  ├─ OS Version: $(lsb_release -ds 2>/dev/null || cat /etc/*release 2>/dev/null | head -n1)"
        echo -e "  ├─ Memory: $(free -h | awk '/^Mem:/ {print $2}')"
        echo -e "  ├─ Disk Space: $(df -h / | awk 'NR==2 {print $4}') available"
        echo -e "  └─ PHP Memory Limit: $(php -r 'echo ini_get("memory_limit");')\n"
    fi
}

# Main function
main() {
    check_root
    check_ubuntu_version
    backup_existing_configs
    update_and_upgrade
    install_required_packages
    add_php_repository
    get_fqdn_or_ip
    install_php_mysql_nginx
    install_composer
    setup_pteroca
    patch_php_api
    set_permissions
    add_cron_job
    configure_nginx_with_fqdn_or_ip
    get_database_password
    check_and_delete_existing_db_user
    setup_mysql
    configure_pteroca_database
    configure_pteroca_system
    check_for_errors
}

main
