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

### DHT 爬虫

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
目录、DHT 状态目录和 bootstrap 节点等选项。

`bind_addr` 支持 IPv4 和 IPv6。`listeners` 取值范围为 `1-64`，
表示启动的独立 libtorrent session 数量；每个 session 维护自己的
DHT 状态，并绑定一个连续端口，端口从 `first-port` 开始。请确保
防火墙允许对应端口。

按 `Ctrl-C` 或发送 `SIGTERM` 可以有序退出。退出前，程序会把每个
session 的节点 ID 和 libtorrent 导出的 DHT 路由状态分别保存到
`dht_state/session-<session-id>-port-<port>.state`。下次以相同端口启动时
会默认加载对应状态，从而保持节点 ID 并加快重新加入 DHT 网络。

可以用 `--dht-state-dir PATH` 修改状态目录。需要放弃已有节点 ID 和路由状态时，
使用 `--reinitialize-dht` 启动；程序会在启动时删除对应旧状态，新状态会在本次
程序有序退出时写入。

### HTTP Tracker

CMake 还会生成独立的 `tracker_server` 程序。它不创建自己的 DHT session，
而是通过 TCP RPC 请求正在运行的 `dht_db` 使用现有 DHT 路由表执行
`get_peers` 查询。

先启动 DHT 爬虫。tracker RPC 默认只监听本机回环地址：

```shell
./build/dht_db \
  --tracker-rpc-bind 127.0.0.1 \
  --tracker-rpc-port 19091
```

再单独启动 HTTP tracker：

```shell
./build/tracker_server \
  --bind 0.0.0.0 \
  --port 8080 \
  --crawler-host 127.0.0.1 \
  --crawler-port 19091 \
  --lookup-timeout 10 \
  --interval 60
```

tracker announce 地址为：

```text
http://<tracker-host>:8080/announce
```

`tracker_server` 支持标准 GET `/announce` 请求中的二进制百分号编码
`info_hash`，并以 compact `peers`/`peers6` 格式回复 DHT 查询结果。运行日志会
显示请求来源、Hash、客户端上报端口、event、回复数量及每个 peer 地址。
`GET /health` 可用于简单健康检查。

该 tracker 是无状态的 DHT 查询代理：它不缓存 swarm，也不会把发起 HTTP
announce 的客户端写入 DHT。后者无法由爬虫代发，因为 DHT 会把网络来源识别为
爬虫主机，而不是 tracker 客户端。RPC 查询使用固定工作线程、有界队列、同 Hash
请求合并和超时控制，不会创建 torrent 或占用爬虫的 metadata 下载任务。

RPC 绑定失败时，`dht_db` 会记录错误并继续原有爬虫功能。无需 tracker 功能时可用
`--disable-tracker-rpc` 禁用；如果 tracker 与爬虫位于不同主机，应通过防火墙或
受信网络限制 RPC 端口，避免公开暴露 DHT 查询接口。

### 结果查看

默认会生成 `tmp`、`torrents` 目录和 `dht_crawler.db` 数据库。
数据库记录种子 Hash、资源名、提供元数据的 peer 和发现时间；
`torrents` 目录按 Hash 保存 `.torrent` 文件。

### 免责声明

本程序使用 libtorrent 构建和维护 DHT 节点。增加监听端口或并发任务数
可能显著提高 CPU、磁盘和网络开销，请自行评估流量和运行成本。
