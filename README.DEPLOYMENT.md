# Manual uniTicket Deployment Guide for Debian 11

This guide provides a detailed, step-by-step process for manually deploying Branch Twist Ticketing on a Debian 11 server. By following these instructions, you can understand each component of the deployment process that the automated script handles.

## 1. System Preparation

### Update and upgrade your system

```bash
# Update package lists
apt update

# Upgrade installed packages
apt upgrade -y
```

### Install required dependencies

```bash
# Install system dependencies
sudo apt install -y xmlsec1 mariadb-server libmariadb-dev python3-dev python3-pip libssl-dev libsasl2-dev libldap2-dev nginx supervisor build-essential libffi-dev git redis-server poppler-utils gobject-introspection libpango-1.0-0 libpangocairo-1.0-0 libcairo2 libharfbuzz0b libpangoft2-1.0-0 libjpeg-dev libffi-dev gettext

# Install Let's Encrypt tools
sudo apt install -y certbot python3-certbot-nginx
```

### Install wkhtmltopdf for PDF generation

```bash
# Download the wkhtmltopdf package
wget https://github.com/wkhtmltopdf/packaging/releases/download/0.12.6.1-2/wkhtmltox_0.12.6.1-2.bullseye_amd64.deb

# Install the package
dpkg -i wkhtmltox_0.12.6.1-2.bullseye_amd64.deb

# Fix any missing dependencies
apt install -f -y

# Remove the downloaded file
rm wkhtmltox_0.12.6.1-2.bullseye_amd64.deb
```

## 2. Database Setup

### Secure the MariaDB Installation

```bash
# Run the MySQL secure installation script
mysql_secure_installation
```

During this process, you'll:

- Set a root password --> EEsfypYbdeOTWoXfCnCGPpWb
- Remove anonymous users
- Disallow root login remotely
- Remove test database
- Reload privilege tables

### Create Database and User

```bash
# Generate a random password (or use your own)
DB_PASS=$(openssl rand -base64 16)
echo "Generated Database Password: $DB_PASS"

# Create the database
mysql -u root -p -e "CREATE DATABASE IF NOT EXISTS uniticket CHARACTER SET = 'utf8' COLLATE = 'utf8_general_ci';"

# Create the database user
mysql -u root -p -e "CREATE USER IF NOT EXISTS 'uniticket_user'@'localhost' IDENTIFIED BY '$DB_PASS';"

# Grant privileges
mysql -u root -p -e "GRANT ALL PRIVILEGES ON uniticket.* TO 'uniticket_user'@'localhost';"

# Apply changes
mysql -u root -p -e "FLUSH PRIVILEGES;"
```

## 3. Application Installation

### Install virtualenv

```bash
# Install virtualenv globally
pip3 install virtualenv
```

### Clone the repository

```bash
# Define the installation directory (use absolute paths for production)
INSTALL_DIR="/opt/uniticket"

# Create the installation directory if it doesn't exist
mkdir -p $INSTALL_DIR

# Clone the uniTicket repository
git clone https://github.com/BranchTwist/branch-twist-ticketing $INSTALL_DIR
cd $INSTALL_DIR
```

### Create the virtual environment

```bash
# Create the virtual environment
python3 -m virtualenv $INSTALL_DIR/uniticket.env

# Activate the virtual environment
source $INSTALL_DIR/uniticket.env/bin/activate
```

### Install Python dependencies

```bash
# Install Python dependencies
pip3 install -r requirements.txt

# Install uWSGI
pip3 install uwsgi
```

## 5. Application Configuration

### Generate random keys

```bash
# Generate a random secret key for Django
SECRET_KEY=$(openssl rand -base64 32)
echo "Django SECRET_KEY: $SECRET_KEY"

# Generate random CAPTCHA keys
CAPTCHA_SECRET=$(openssl rand -base64 12)
echo "CAPTCHA_SECRET: $CAPTCHA_SECRET"
CAPTCHA_SALT=$(openssl rand -base64 12)
echo "CAPTCHA_SALT: $CAPTCHA_SALT"
```

### Create the settingslocal.py file

```bash
# Create the settingslocal.py file with proper configuration
nano $INSTALL_DIR/uniticket/uni_ticket_project/settingslocal.py
```

In the editor, paste settingslocal.py content

### Fix permissions

```bash
# Set ownership of the settings file
chown root $INSTALL_DIR/uniticket/uni_ticket_project/settingslocal.py
chmod 600 $INSTALL_DIR/uniticket/uni_ticket_project/settingslocal.py
```

### Get Bootstrap Italia template

```bash
# Download Bootstrap Italia base template
curl https://raw.githubusercontent.com/italia/design-django-theme/master/bootstrap_italia_template/templates/bootstrap-italia-base.html --output $INSTALL_DIR/uniticket/templates/base-setup.html
```

## 6. Application Initialization

### Create data directories

```bash
# Create necessary data directories
mkdir -p $INSTALL_DIR/uniticket/data/media
mkdir -p $INSTALL_DIR/uniticket/data/static
```

### Run migrations and collect static files

```bash
# Open the uniticket folder
cd uniticket

# Run migrations
python manage.py migrate

# Compile translation messages
python manage.py compilemessages

# Collect static files
python manage.py collectstatic --noinput

# Create superuser
python manage.py createsuperuser
```

Nome utente: admin_bt
Email address: <admin@branchtwist.com>
Password: ccIOhmxlNQCo

## 7. Web Server Configuration

### Create log directories

```bash
# Create log directories for uWSGI and Daphne
mkdir -p /var/log/uwsgi
chown root:root /var/log/uwsgi
chmod 755 /var/log/uwsgi
```

### Configure uWSGI

```bash
# Copy the uwsgi.ini file
cp $INSTALL_DIR/uwsgi_setup/uwsgi.ini /etc/uwsgi.ini

# Copy the uwsgi_params file
cp $INSTALL_DIR/uwsgi_setup/uwsgi_params /etc/nginx/uwsgi_params

# Update the configuration with the correct user, group, and paths
# Ensure user and group are set to root
sed -i "s#uid         = .*#uid         = root#" /etc/uwsgi.ini
sed -i "s#gid         = .*#gid         = root#" /etc/uwsgi.ini
sed -i "s#chdir       = .*#chdir       = $INSTALL_DIR/uniticket#" /etc/uwsgi.ini
sed -i "s#home        = .*#home        = $INSTALL_DIR/uniticket.env#" /etc/uwsgi.ini
sed -i "s#daemonize   = .*#daemonize   = /var/log/uwsgi/uniticket.log#" /etc/uwsgi.ini

# Fix the virtualenv path to use absolute path instead of %(base) variable
sed -i "s#virtualenv  = %(base)/uniticket.env#virtualenv  = $INSTALL_DIR/uniticket.env#" /etc/uwsgi.ini

# Ensure DJANGO_SETTINGS_MODULE is correctly formatted (no spaces around =)
sed -i "s#env         = DJANGO_SETTINGS_MODULE = .*#env = DJANGO_SETTINGS_MODULE=uni_ticket_project.settings#" /etc/uwsgi.ini

# Fix the touch-reload path to use the correct location
sed -i "s#touch-reload    = %(base)/%(project)/uni_ticket_project/settings.py#touch-reload    = $INSTALL_DIR/uniticket/uni_ticket_project/settings.py#" /etc/uwsgi.ini
```

### Create uWSGI service

```bash
# Create the systemd service file
cat << EOF > /etc/systemd/system/uwsgi.service
[Unit]
Description=uWSGI Emperor
After=syslog.target network.target

[Service]
ExecStart=$INSTALL_DIR/uniticket.env/bin/uwsgi --ini /etc/uwsgi.ini
Restart=always
KillSignal=SIGQUIT
Type=notify
StandardError=syslog
NotifyAccess=all
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF
```

### Configure Nginx

```bash
# Create the Nginx configuration file
cat << EOF > /etc/nginx/sites-available/uniticket
# the upstream component nginx needs to connect to
upstream uniticket {
    server 127.0.0.1:3000;
}

# configuration of the server
server {
    # the port your site will be served on
    listen      80;
    server_name support.branchtwist.com;
    
    access_log /var/log/nginx/uniticket.access.log;
    error_log  /var/log/nginx/uniticket.error.log error;
    
    # Redirect to HTTPS
    location / {
        return 301 https://\$host\$request_uri;
    }
}

server {
    server_name support.branchtwist.com;
    listen 443 ssl;

    # SSL certificates - these will be updated by certbot but we need placeholders
    # to prevent configuration errors before obtaining the certificates
    ssl_certificate /etc/ssl/certs/ssl-cert-snakeoil.pem;
    ssl_certificate_key /etc/ssl/private/ssl-cert-snakeoil.key;

    access_log /var/log/nginx/uniticket.log;
    error_log  /var/log/nginx/uniticket.log error;

    # SSL HARDENING
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;
    ssl_session_timeout 10m;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";
    add_header X-Robots-Tag none;

    # Django static (use absolute paths)
    location /static  {
        alias $INSTALL_DIR/uniticket/data/static;
        autoindex off;
    }

    # Django media (use absolute paths)
    location /media  {
        alias $INSTALL_DIR/uniticket/data/media;
        autoindex off;
    }

    # this is the endpoint of the channels routing
    location /ws/ {
        proxy_pass http://localhost:8089; # daphne (ASGI) listening on port 8089
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";

        proxy_connect_timeout 6h;
        proxy_read_timeout 6h;
        proxy_send_timeout 6h;
    }

    # Finally, send all non-media requests to the Django server.
    location / {
        uwsgi_pass  uniticket;
        uwsgi_param HTTP_X_FORWARDED_PROTOCOL https;
        uwsgi_param SCRIPT_NAME "";
        uwsgi_param UWSGI_SCHEME https;

        # deny iFrame
        add_header X-Frame-Options "DENY";

        uwsgi_connect_timeout 75s;
        uwsgi_read_timeout 33;
        client_max_body_size 10m;
        include     /etc/nginx/uwsgi_params;
    }
}
EOF

# Install the default self-signed certificates if they don't exist
apt install -y ssl-cert
```

### Configure Daphne for WebSockets

```bash
# Create the supervisor configuration for Daphne
cat << EOF > /etc/supervisor/conf.d/daphne.conf
[program:django-daphne]
environment=PATH="$INSTALL_DIR/uniticket.env/bin:%(ENV_PATH)s"
directory=$INSTALL_DIR/uniticket
command=$INSTALL_DIR/uniticket.env/bin/daphne -b 127.0.0.1 -p 8089 uni_ticket_project.asgi:channel_layer
user=root
group=root
stopasgroup=true
autostart=true

# logging
stdout_logfile=/var/log/uwsgi/daphne.log
stdout_logfile_maxbytes=1000MB
stdout_logfile_backups=10
stdout_capture_maxbytes=1000MB
stdout_events_enabled=false
stderr_logfile=/var/log/uwsgi/daphne.err
stderr_logfile_maxbytes=1000MB
stderr_logfile_backups=10
EOF
```

## 8. Finalize Installation

### Set up backup job

```bash
# Copy the backup script
cp $INSTALL_DIR/uwsgi_setup/backup.sh /opt/backup-uniticket.sh
chmod +x /opt/backup-uniticket.sh

# Update any paths in the backup script to use absolute paths
sed -i "s#~/uniticket#$INSTALL_DIR/uniticket#g" /opt/backup-uniticket.sh

# Add a cron job for daily backups
(crontab -l 2>/dev/null; echo "0 1 * * * /opt/backup-uniticket.sh") | crontab -
```

### Apply server tuning

```bash
# Apply server tuning from the provided script
bash $INSTALL_DIR/uwsgi_setup/server-tuning.sh
```

### Verify Redis configuration

```bash
# Check if Redis is running
systemctl status redis-server

# Ensure Redis is enabled to start at boot
systemctl enable redis-server

# Test Redis connectivity
redis-cli ping  # Should return PONG
```

### Obtain SSL certificate from Let's Encrypt

```bash
# Obtain and install SSL certificate
certbot --nginx -d support.branchtwist.com --non-interactive --agree-tos --email support@branchtwist.com
```

### Enable the Nginx site and start all services

```bash
# Enable the uniticket site and disable the default site
ln -sf /etc/nginx/sites-available/uniticket /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Reload systemd configuration
systemctl daemon-reload

# Enable services to start on boot
systemctl enable uwsgi
systemctl enable nginx
systemctl enable supervisor

# Start services
systemctl restart supervisor
systemctl restart uwsgi
systemctl restart nginx
```

## 9. Post-Installation Verification

### Verify services are running

```bash
# Check status of all services
systemctl status nginx
systemctl status uwsgi
systemctl status supervisor
systemctl status redis-server
```

### Verify the website

```bash
# Test the website using curl (should redirect to HTTPS)
curl -I http://support.branchtwist.com

# Test SSL access (should return 200 OK)
curl -k -I https://support.branchtwist.com

# Test the admin login page (should redirect to login)
curl -I https://support.branchtwist.com/admin/

# Check that the admin login page loads correctly
curl -I https://support.branchtwist.com/admin/login/
```

### Check log files for errors

```bash
# Check Nginx logs
tail -n 50 /var/log/nginx/uniticket.log
tail -n 50 /var/log/nginx/uniticket.error.log

# Check uWSGI logs
tail -n 50 /var/log/uwsgi/uniticket.log

# Check Daphne logs
tail -n 50 /var/log/uwsgi/daphne.log
tail -n 50 /var/log/uwsgi/daphne.err
```

### Test database connection

```bash
# Test database connection
mysql -u uniticket_user -p uniticket -e "SHOW TABLES;"
```

## 10. Additional Security Measures

### Set up a firewall with UFW

```bash
# Install UFW
apt install -y ufw

# Set up basic rules
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp

# Enable the firewall
ufw enable

# Check status
ufw status
```

### Install Fail2Ban to protect against brute force attacks

```bash
# Install Fail2Ban
apt install -y fail2ban

# Start and enable the service
systemctl start fail2ban
systemctl enable fail2ban

# Check status
systemctl status fail2ban
```

### Set up automatic security updates

```bash
# Install unattended upgrades
apt install -y unattended-upgrades apt-listchanges

# Configure unattended upgrades
dpkg-reconfigure -plow unattended-upgrades
```

## 11. Initial Application Setup

After the installation is complete, you'll need to access the admin interface to set up the basic structure:

1. Open <https://support.branchtwist.com/admin/> in your browser
2. Log in with the superuser credentials created earlier
3. Create organizational areas
4. Set up ticket categories
5. Configure user roles (manager, operator)
6. Set up any custom fields needed for your tickets

This completes the manual deployment of uniTicket on Debian 11.
