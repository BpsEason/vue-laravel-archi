# docker/grpc/Dockerfile
FROM php:8.3-cli-alpine AS grpc-builder

WORKDIR /app/grpc-service

# 安裝系統依賴和 PHP 擴展
RUN apk add --no-cache \
    git \
    unzip \
    libzip-dev \
    libpng-dev \
    jpeg-dev \
    libwebp-dev \
    freetype-dev \
    libjpeg-turbo-dev \
    webp-dev \
    grpc-dev \
    protobuf-dev \
    build-base # 編譯所需，用於 gd 擴展

# 安裝 PHP gRPC 和 Protobuf 擴展
RUN pecl install grpc protobuf \
    && docker-php-ext-enable grpc protobuf \
    && docker-php-ext-configure gd --with-freetype --with-jpeg --with-webp \
    && docker-php-ext-install -j$(nproc) gd

# 清理編譯工具
RUN apk del build-base

# 安裝 Composer
COPY --from=composer/composer:latest-bin /composer /usr/bin/composer

# 複製 gRPC 服務的 composer.json 和 lock 文件
COPY grpc-service/composer.json grpc-service/composer.lock ./

# 安裝 Composer 依賴
RUN composer install --no-dev --optimize-autoloader

# 複製所有 gRPC 服務程式碼和 proto 文件
COPY grpc-service .

# 從 RoadRunner releases 下載 rr 二進制文件
ARG RR_VERSION=2.12.0 # 或您希望使用的最新穩定版本
RUN wget https://github.com/roadrunner-server/roadrunner/releases/download/v${RR_VERSION}/rr-v${RR_VERSION}-linux-amd64.tar.gz -O /tmp/rr.tar.gz \
    && tar -xzf /tmp/rr.tar.gz -C /usr/local/bin rr \
    && rm /tmp/rr.tar.gz \
    && chmod +x /usr/local/bin/rr

# 生成 PHP gRPC stubs
# 注意: grpc_php_plugin 需要在 PATH 中
RUN composer run proto:generate

FROM php:8.3-cli-alpine

WORKDIR /app/grpc-service

COPY --from=grpc-builder /app/grpc-service/vendor ./vendor
COPY --from=grpc-builder /app/grpc-service/src ./src
COPY --from=grpc-builder /app/grpc-service/proto ./proto
COPY --from=grpc-builder /app/grpc-service/server.php ./server.php
COPY --from=grpc-builder /app/grpc-service/.rr.yaml ./.rr.yaml
COPY --from=grpc-builder /usr/local/bin/rr /usr/local/bin/rr

# 安裝運行時所需的 PHP 擴展
RUN apk add --no-cache \
    grpc-dev \
    protobuf-dev && \
    pecl install grpc protobuf \
    && docker-php-ext-enable grpc protobuf \
    && docker-php-ext-install gd

# 暴露 gRPC 端口
EXPOSE 50051

# 啟動 gRPC RoadRunner server
CMD ["rr", "serve", "-c", ".rr.yaml", "--debug"]
