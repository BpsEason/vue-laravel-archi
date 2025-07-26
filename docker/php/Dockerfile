# docker/php/Dockerfile
FROM php:8.3-fpm-alpine

# 安裝系統依賴和 PHP 擴展
RUN apk add --no-cache \
    nginx \ 
    libzip-dev \
    libpng-dev \
    jpeg-dev \
    libwebp-dev \
    freetype-dev \
    libjpeg-turbo-dev \
    webp-dev \
    mysql-client \
    git \
    unzip \
    grpc-dev \
    protobuf-dev \
    build-base # 編譯所需，用於 gd 擴展

# 安裝 PHP 擴展 (新增 grpc, protobuf)
RUN pecl install grpc protobuf \
    && docker-php-ext-enable grpc protobuf \
    && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
    && docker-php-ext-install -j$(nproc) gd pdo_mysql zip opcache redis

# 清理編譯工具
RUN apk del build-base

# 安裝 Composer
COPY --from=composer/composer:latest-bin /composer /usr/bin/composer

# 設定工作目錄為 /var/www/html
WORKDIR /var/www/html

# 複製 backend 程式碼
COPY backend ./backend

# 暴露端口
EXPOSE 9000 # PHP-FPM
EXPOSE 80   # Nginx

# CMD 將被 docker-compose.yml 中的 `command` 覆蓋
