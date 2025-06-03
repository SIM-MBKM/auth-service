#!/bin/bash

# Destination of env file inside container
ENV_FILE="/var/www/.env"

#####################################
# Laravel Application Setup
#####################################

echo "Starting Laravel application setup..."

# Copy .env.example to .env if .env doesn't exist
if [ ! -f "/var/www/html/.env" ] && [ -f "/var/www/html/.env.example" ]; then
    echo "Creating .env file from .env.example..."
    cp /var/www/html/.env.example /var/www/html/.env
fi

# Install/Update composer dependencies if needed
echo "Checking composer dependencies..."
cd /var/www/html

if [ ! -d "vendor" ] || [ ! -f "vendor/autoload.php" ]; then
    echo "Installing composer dependencies (fresh install)..."
    composer install --optimize-autoloader --no-interaction --prefer-dist
elif [ "composer.json" -nt "vendor/autoload.php" ]; then
    echo "Updating composer dependencies (composer.json is newer)..."
    composer install --optimize-autoloader --no-interaction --prefer-dist
else
    echo "Composer dependencies are up to date."
fi

# Dump optimized autoloader
echo "Optimizing composer autoloader..."
composer dump-autoload --optimize --no-interaction

# Generate Laravel application key if not exists
if [ -f "/var/www/html/.env" ]; then
    if ! grep -q "APP_KEY=base64:" /var/www/html/.env || grep -q "APP_KEY=$" /var/www/html/.env; then
        echo "Generating Laravel application key..."
        cd /var/www/html
        php artisan key:generate --no-interaction --force
    else
        echo "Laravel application key already exists."
    fi
else
    echo "No .env file found, skipping key generation."
fi

# Create storage symlink if it doesn't exist
if [ ! -L "/var/www/html/public/storage" ]; then
    echo "Creating storage symlink..."
    cd /var/www/html
    php artisan storage:link --no-interaction 2>/dev/null || true
fi

# Set proper permissions
echo "Setting proper permissions..."
chown -R www-data:www-data /var/www/html/storage /var/www/html/bootstrap/cache
chmod -R 775 /var/www/html/storage /var/www/html/bootstrap/cache

# Clear and cache configuration for better performance
echo "Optimizing Laravel configuration..."
cd /var/www/html

# Clear all caches first
php artisan config:clear --no-interaction 2>/dev/null || true
php artisan cache:clear --no-interaction 2>/dev/null || true  
php artisan view:clear --no-interaction 2>/dev/null || true
php artisan route:clear --no-interaction 2>/dev/null || true

# Run Laravel package discovery
echo "Running Laravel package discovery..."
php artisan package:discover --no-interaction 2>/dev/null || true

# Cache configuration in production environment
if [ "$APP_ENV" = "production" ]; then
    echo "Caching configuration for production..."
    php artisan config:cache --no-interaction 2>/dev/null || true
    php artisan route:cache --no-interaction 2>/dev/null || true
    php artisan view:cache --no-interaction 2>/dev/null || true
else
    echo "Development mode - skipping config caching."
fi

#####################################
# Database Setup (Optional)
#####################################

# Test database connection if configured
if [ -f "/var/www/html/.env" ] && grep -q "DB_CONNECTION=" /var/www/html/.env; then
    echo "Testing database connection..."
    cd /var/www/html
    
    # Test database connection with timeout
    timeout 10s php artisan migrate:status 2>/dev/null && echo "✅ Database connection: SUCCESS" || echo "⚠️  Database connection: FAILED (continuing anyway)"
    
    # Auto migrate in development if DB is available
    if [ "$APP_ENV" = "local" ] && timeout 5s php artisan migrate:status >/dev/null 2>&1; then
        echo "Running database migrations (development mode)..."
        php artisan migrate --force --no-interaction 2>/dev/null || echo "⚠️  Migration failed (continuing anyway)"
    fi
else
    echo "No database configuration found."
fi

#####################################
# Environment Variables Setup
#####################################

# Loop through XDEBUG, PHP_IDE_CONFIG and REMOTE_HOST variables and check if they are set.
# If they are not set then check if we have values for them in the env file, if the env file exists. If we have values
# in the env file then add exports for these in in the ~./bashrc file.
for VAR in XDEBUG PHP_IDE_CONFIG REMOTE_HOST
do
  if [ -z "${!VAR}" ] && [ -f "${ENV_FILE}" ]; then
    VALUE=$(grep $VAR $ENV_FILE | cut -d '=' -f 2-)
    if [ ! -z "${VALUE}" ]; then
      # Before adding the export we clear the value, if set, to prevent duplication.
      sed -i "/$VAR/d"  ~/.bashrc
      echo "export $VAR=$VALUE" >> ~/.bashrc;
    fi
  fi
done

# Source the .bashrc file so that the exported variables are available.
. ~/.bashrc

# If there is still no value for the REMOTE_HOST variable then we set it to the default of host.docker.internal. This
# value will be sufficient for windows and mac environments.
if [ -z "${REMOTE_HOST}" ]; then
  REMOTE_HOST="host.docker.internal"
  sed -i "/REMOTE_HOST/d"  ~/.bashrc
  echo "export REMOTE_HOST=\"$REMOTE_HOST\"" >> ~/.bashrc;
  . ~/.bashrc
fi

#####################################
# Services Setup
#####################################

# Start the cron service.
echo "Starting cron service..."
service cron start

#####################################
# Xdebug Configuration
#####################################

# Toggle xdebug
if [ "true" == "$XDEBUG" ] && [ ! -f /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini ]; then
  echo "Enabling Xdebug..."
  # Remove PHP_IDE_CONFIG from cron file so we do not duplicate it when adding below
  sed -i '/PHP_IDE_CONFIG/d' /etc/cron.d/laravel-scheduler
  if [ ! -z "${PHP_IDE_CONFIG}" ]; then
    # Add PHP_IDE_CONFIG to cron file. Cron by default does not load enviromental variables. The server name, set here, is
    # used by PHPSTORM for path mappings
    echo -e "PHP_IDE_CONFIG=\"$PHP_IDE_CONFIG\"\n$(cat /etc/cron.d/laravel-scheduler)" > /etc/cron.d/laravel-scheduler
  fi
  # Enable xdebug estension and set up the docker-php-ext-xdebug.ini file with the required xdebug settings
  docker-php-ext-enable xdebug && \
  echo "xdebug.remote_enable=1" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini; \
  echo "xdebug.remote_autostart=1" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini; \
  echo "xdebug.remote_connect_back=0" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini; \
  echo "xdebug.remote_host=$REMOTE_HOST" >> /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini;

elif [ -f /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini ]; then
  echo "Disabling Xdebug..."
  # Remove PHP_IDE_CONFIG from cron file if already added
  sed -i '/PHP_IDE_CONFIG/d' /etc/cron.d/laravel-scheduler
  # Remove Xdebug config file disabling xdebug
  rm -rf /usr/local/etc/php/conf.d/docker-php-ext-xdebug.ini
fi

#####################################
# Final Setup
#####################################

echo "Laravel application setup completed!"
echo "========================================"
echo "Laravel Version: $(cd /var/www/html && php artisan --version 2>/dev/null || echo 'Unknown')"
echo "Environment: ${APP_ENV:-local}"
echo "Debug Mode: ${APP_DEBUG:-false}"
echo "PHP-FPM Status: Starting..."
echo "Access URL: http://localhost:8080"
echo "========================================"

# Health check - Test if Laravel can bootstrap
echo "Running Laravel health check..."
cd /var/www/html
php -r "
try {
    require_once 'vendor/autoload.php';
    \$app = require_once 'bootstrap/app.php';
    echo '✅ Laravel Bootstrap: SUCCESS' . PHP_EOL;
    echo '✅ App Name: ' . \$app->make('config')->get('app.name', 'Laravel') . PHP_EOL;
} catch (Exception \$e) {
    echo '❌ Laravel Bootstrap: FAILED - ' . \$e->getMessage() . PHP_EOL;
    exit(1);
}
" || echo "⚠️  Laravel health check failed"

# Execute the main command
exec "$@"