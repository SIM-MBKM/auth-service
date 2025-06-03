FROM php:8.3-fpm

ENV COMPOSER_MEMORY_LIMIT='-1'
ENV PS1="\u@\h:\w\\$ "
ENV TZ="Asia/Jakarta"

# Install dependencies
RUN apt-get update && \
    apt-get install -y --force-yes --no-install-recommends \
        libmemcached-dev libmcrypt-dev libreadline-dev libgmp-dev \
        libzip-dev libz-dev libpq-dev libjpeg-dev libpng-dev \
        libfreetype6-dev libssl-dev openssh-server libmagickwand-dev \
        git cron nano libxml2-dev

# Install PHP extensions
RUN docker-php-ext-install soap exif pcntl intl gmp zip pdo_mysql pdo_pgsql bcmath sockets

# Install PECL extensions
RUN pecl install redis mongodb imagick xdebug memcached && \
    docker-php-ext-enable redis mongodb imagick memcached

# Configure GD
RUN docker-php-ext-configure gd --with-freetype --with-jpeg && \
    docker-php-ext-install gd

# Install Composer
RUN curl -s http://getcomposer.org/installer | php && \
    mv composer.phar /usr/local/bin/composer

# Laravel Schedule Cron Job
RUN echo "* * * * * root /usr/local/bin/php /var/www/html/artisan schedule:run >> /dev/null 2>&1" >> /etc/cron.d/laravel-scheduler
RUN chmod 0644 /etc/cron.d/laravel-scheduler

# Copy PHP configurations
ADD ./php/local.ini /usr/local/etc/php/conf.d
COPY ./php/www.conf /usr/local/etc/php-fpm.d/www.conf

# Create aliases
RUN echo '#!/bin/bash\n/usr/local/bin/php /var/www/html/vendor/bin/dep "$@"' > /usr/bin/dep && chmod +x /usr/bin/dep
RUN echo '#!/bin/bash\n/usr/local/bin/php /var/www/html/artisan "$@"' > /usr/bin/art && chmod +x /usr/bin/art
RUN echo '#!/bin/bash\n/usr/local/bin/php /var/www/html/artisan migrate "$@"' > /usr/bin/migrate && chmod +x /usr/bin/migrate
RUN echo '#!/bin/bash\n/usr/local/bin/php /var/www/html/artisan migrate:fresh --seed' > /usr/bin/fresh && chmod +x /usr/bin/fresh

RUN rm -r /var/lib/apt/lists/*

WORKDIR /var/www/html

# ✅ COPY ALL Laravel directories (with trailing slash for directories)
COPY app/ ./app/
COPY bootstrap/ ./bootstrap/
COPY config/ ./config/
COPY public/ ./public/
COPY resources/ ./resources/
COPY routes/ ./routes/
COPY storage/ ./storage/
COPY tests/ ./tests/
COPY scripts/ ./scripts/

# ✅ COPY individual files one by one (correct syntax)
COPY artisan ./
COPY composer.json ./
COPY composer.lock ./
COPY .env.example ./
COPY phpunit.xml ./
COPY vite.config.js ./
COPY package.json ./
COPY package-lock.json ./
COPY README.md ./
COPY test_consumer.php ./
COPY .editorconfig ./
COPY .gitattributes ./
COPY .gitignore ./
COPY .prettierrc ./
COPY gcs-secret-key.json ./

COPY .env ./

# Create Laravel directories if they don't exist
RUN mkdir -p storage/logs storage/framework/{cache,sessions,views} bootstrap/cache

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html && \
    chmod -R 755 /var/www/html/storage && \
    chmod -R 755 /var/www/html/bootstrap/cache

# Copy and setup entrypoint
COPY ./php/docker-entrypoint-jenkins.sh /usr/local/bin/docker-entrypoint-jenkins.sh
RUN chmod +x /usr/local/bin/docker-entrypoint-jenkins.sh

ENTRYPOINT ["docker-entrypoint-jenkins.sh"]
EXPOSE 9000
CMD ["php-fpm"]