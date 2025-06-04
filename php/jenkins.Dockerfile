FROM dimasfadilah/laravel-php-base:8.3-fpm

# Copy project-specific PHP-FPM configuration
COPY ./php/www.conf /usr/local/etc/php-fpm.d/www.conf

# Copy Laravel application files
COPY app/ ./app/
COPY bootstrap/ ./bootstrap/
COPY config/ ./config/
COPY public/ ./public/
COPY routes/ ./routes/
COPY storage/ ./storage/
COPY tests/ ./tests/

# Copy individual files
COPY artisan ./
COPY composer.json ./
COPY composer.lock ./
COPY .env.example ./
COPY phpunit.xml ./
COPY vite.config.js ./
COPY package.json ./
# COPY package-lock.json ./
COPY README.md ./
COPY .editorconfig ./
COPY .gitattributes ./
COPY .gitignore ./
# COPY .prettierrc ./
COPY gcs-secret-key.json ./
COPY .env ./

# Install Composer dependencies
RUN composer install --no-dev --optimize-autoloader

# Create Laravel directories and set permissions
RUN mkdir -p storage/logs storage/framework/{cache,sessions,views} bootstrap/cache && \
    chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html/storage && \
    chmod -R 755 /var/www/html/bootstrap/cache

# Copy and setup project-specific entrypoint
COPY ./php/docker-entrypoint-jenkins.sh /usr/local/bin/docker-entrypoint-jenkins.sh
RUN chmod +x /usr/local/bin/docker-entrypoint-jenkins.sh


RUN echo "[global]\ndaemonize = no\n[www]\nlisten = 0.0.0.0:9002" > /usr/local/etc/php-fpm.d/zz-docker.conf
# RUN echo "[www]\nlisten = 0.0.0.0:9002" > /usr/local/etc/php-fpm.d/zzz-custom.conf

ENTRYPOINT ["docker-entrypoint-jenkins.sh"]
EXPOSE 9002
CMD ["php-fpm"]