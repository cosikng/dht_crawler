## 一个简单的 DHT 爬虫

### 依赖库

```text
libtorrent-rasterbar >= 2.0
SQLite3
```

### 编译

```shell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

### 执行

兼容原有位置参数：

```shell
./build/dht_db bind_addr listeners
```

也可以使用完整选项：

```shell
./build/dht_db \
  --bind 0.0.0.0 \
  --listeners 1 \
  --first-port 6881 \
  --max-active 200 \
  --metadata-timeout 30 \
  --retry-delay 60
```

使用 `./build/dht_db --help` 查看数据库路径、临时目录、torrent
目录和 bootstrap 节点等选项。

`bind_addr` 支持 IPv4 和 IPv6。`listeners` 取值范围为 `1-64`，
表示启动的独立 libtorrent session 数量；每个 session 维护自己的
DHT 状态，并绑定一个连续端口，端口从 `first-port` 开始。请确保
防火墙允许对应端口。

按 `Ctrl-C` 或发送 `SIGTERM` 可以有序退出。

### 结果查看

默认会生成 `tmp`、`torrents` 目录和 `dht_crawler.db` 数据库。
数据库记录种子 Hash、资源名、提供元数据的 peer 和发现时间；
`torrents` 目录按 Hash 保存 `.torrent` 文件。

### 免责声明

本程序使用 libtorrent 构建和维护 DHT 节点。增加监听端口或并发任务数
可能显著提高 CPU、磁盘和网络开销，请自行评估流量和运行成本。
