<?php

// grpc-service/server.php
require __DIR__ . '/vendor/autoload.php';

use Spiral\RoadRunner\Worker;
use Spiral\RoadRunner\GRPC\GRPC;
use Grpc\ImageProcessor\Services\ImageProcessorImplementation;
use Grpc\ImageProcessor\ImageProcessorGrpcInterface;

// 創建 Worker
$worker = Worker::create();

// 創建 gRPC 服務器
$grpc = new GRPC();

// 註冊您的 gRPC 服務
$grpc->addService(
    new \ReflectionClass(ImageProcessorGrpcInterface::class),
    new ImageProcessorImplementation()
);

// 啟動 gRPC 服務器
$grpc->serve($worker);

// 注意：RoadRunner 會接管輸出，此行不會直接顯示
// echo "gRPC Image Worker server started...\n";
