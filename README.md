## 一个简单的 DHT 爬虫

支持 Linux（GCC/Clang）和 Windows（MinGW-w64/MSVC），两个平台的功能、网络、
并发和持久化行为保持一致。移植与审计细节见
[AUDIT_AND_OPTIMIZATION_REPORT.md](AUDIT_AND_OPTIMIZATION_REPORT.md)。

### 依赖库

```text
libtorrent-rasterbar >= 2.0.9
SQLite3
Python 3（仅运行集成测试时需要）
```

### 编译

Linux：

```shell
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Windows（MinGW-w64，依赖由 vcpkg 提供）：

```shell
vcpkg install libtorrent sqlite3 --triplet x64-mingw-static
cmake -S . -B build -G Ninja ^
  -DCMAKE_TOOLCHAIN_FILE=%VCPKG_ROOT%/scripts/buildsystems/vcpkg.cmake ^
  -DVCPKG_TARGET_TRIPLET=x64-mingw-static -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

Windows 上会自动链接 `ws2_32`，生成的程序只依赖系统 DLL，可直接复制运行。
MSVC 使用 `x64-windows-static` triplet，可直接用下面的 `msvc-release` 预设。

也可以使用 `CMakePresets.json` 中的预设（Windows 预设需要设置 `VCPKG_ROOT`
环境变量）：

```shell
cmake --preset linux-release      # 或 mingw-release / mingw-debug / msvc-release
cmake --build --preset linux-release
ctest --preset linux-release
```

### 测试

```shell
ctest --test-dir build --output-on-failure
```

`unit_tests` 覆盖 tracker 协议解析、地址格式化、去重缓存内存上限、原子文件替换
以及 SQLite 高并发写入；`integration_tests` 用 Python 标准库驱动编译好的
`tracker_server` 和 `dht_db`，包括畸形请求、慢速连接、句柄泄漏、端口抢占、
优雅退出，以及通过模拟 DHT 节点和 BitTorrent peer 完成的端到端元数据抓取。
测试只使用本机回环地址，不访问公网。

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
目录、DHT 状态目录和 bootstrap 节点等选项。新增选项：

- `--max-active-total N`：全进程并发元数据任务上限，默认 `listeners * max-active`。
- `--dedup-cache-size N`：内存去重缓存的最大条目数，默认 262144，超过后淘汰最旧条目。
- `--dht-save-interval SEC`：定期保存 DHT 状态的间隔，默认 900 秒。
- `--bootstrap-stagger-ms MS`：相邻 session 的启动间隔，默认 200 毫秒，避免同时冲击 bootstrap 节点。

`bind_addr`/`--bind` 支持 IPv4 和 IPv6。`listeners` 取值范围为 `1-64`，
表示启动的独立 libtorrent session 数量；每个 session 维护自己的
DHT 状态，并绑定一个连续端口，端口从 `first-port` 开始。请确保
防火墙允许对应端口的 TCP 和 UDP（Windows 首次监听 `0.0.0.0`/`::` 时会弹出防火墙提示）。
所有 session 共享一个全局 Hash 登记表，同一个 Hash 同一时间只会被一个任务抓取。

#### 双栈（IPv4 + IPv6）

`--bind` 可以写多个地址，用逗号分隔或重复指定（第一次指定会替换默认的
`0.0.0.0`），最多 16 个；IPv6 地址可以带方括号。下面三种写法等价：

```shell
./build/dht_db --bind 0.0.0.0,:: --listeners 4
./build/dht_db --bind 0.0.0.0 --bind [::] --listeners 4
./build/dht_db 0.0.0.0,:: 4
```

每个 session 在所有地址上监听同一个端口，例如 session 0 监听
`0.0.0.0:6881` 和 `[::]:6881`。`0.0.0.0` 表示所有 IPv4 接口，`::` 表示所有
IPv6 接口；libtorrent 将 IPv6 socket 设为仅 IPv6，因此两者可以共用端口，
并在每个监听 socket 上各运行一个 DHT 节点（IPv6 DHT 即 BEP 32）。

与运行两个单栈进程相比，双栈单进程有这些好处：两个地址族共享同一个 Hash
登记表，同一个 Hash 只会被抓取一次（无论从 IPv4 还是 IPv6 收到 announce）；
只有一个数据库写线程、一个 torrent 目录和一个 tracker RPC 端口；每个 session 的
状态文件同时保存两个地址族的节点 ID（日志显示“节点 ID 2”），并按监听地址恢复。
从单栈改为双栈时可以直接沿用旧状态文件：原有地址族保留节点 ID，新增地址族会
生成新的节点 ID。如果主机没有可用的 IPv6 地址，`::` 不会产生任何监听 socket
（具体地址监听失败时只记录 libtorrent 错误），IPv4 部分照常运行。

地址列表不能为空、不能有空项或重复地址（`::` 与 `0:0::0` 视为重复），否则程序
打印用法并以退出码 1 退出。

退出方式：Linux 上按 `Ctrl-C` 或发送 `SIGTERM`/`SIGHUP`；Windows 上按
`Ctrl-C`、`Ctrl-Break` 或关闭控制台窗口（以及注销/关机）。程序会先把已获取的
元数据写入数据库，再保存 DHT 状态，然后并行关闭所有 session。再次发送退出信号
会立即终止进程（退出码 130）。DHT 状态保存到
`dht_state/session-<session-id>-port-<port>.state`，运行期间也会定期保存。
下次以相同端口启动时会默认加载对应状态，从而保持节点 ID 并加快重新加入 DHT 网络。

可以用 `--dht-state-dir PATH` 修改状态目录。需要放弃已有节点 ID 和路由状态时，
使用 `--reinitialize-dht` 启动；程序会在启动时删除对应旧状态，新状态会在本次
程序退出时写入。

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

`tracker_server --bind ::` 同时接受 IPv4 和 IPv6 客户端（其监听 socket 在两个
平台上都显式设为双栈，IPv4 客户端在日志中显示为 `[::ffff:a.b.c.d]:port`）。
爬虫的 tracker RPC 使用相同的监听实现，`--tracker-rpc-bind` 也可以是 IPv6 地址（如 `::1`）。

`tracker_server` 支持标准 GET `/announce` 请求中的二进制百分号编码
`info_hash`，并以 compact `peers`/`peers6` 格式回复 DHT 查询结果。爬虫为双栈时，
查询会同时在 IPv4 和 IPv6 DHT 上进行，但与之前一样，回复的是最先返回 peer 的
那一批结果，因此一次回复可能只包含 `peers` 或只包含 `peers6`。运行日志会
显示请求来源、Hash、客户端上报端口、event、回复数量及每个 peer 地址（客户端
提供的文本会转义控制字符，防止伪造日志行）。`GET /health` 可用于简单健康检查。

每个连接必须在 `lookup-timeout + 3` 秒内发完完整请求头，请求头上限 16 KiB；
未完成的慢速连接由 I/O 线程统一管理，不会占用工作线程。

该 tracker 是无状态的 DHT 查询代理：它不缓存 swarm，也不会把发起 HTTP
announce 的客户端写入 DHT。后者无法由爬虫代发，因为 DHT 会把网络来源识别为
爬虫主机，而不是 tracker 客户端。RPC 查询使用固定工作线程、有界队列、同 Hash
请求合并和超时控制，不会创建 torrent 或占用爬虫的 metadata 下载任务。

RPC 绑定失败时，`dht_db` 会记录错误并继续原有爬虫功能。无需 tracker 功能时可用
`--disable-tracker-rpc` 禁用；如果 tracker 与爬虫位于不同主机，应通过防火墙或
受信网络限制 RPC 端口，避免公开暴露 DHT 查询接口。

### 结果查看

默认会生成 `tmp`、`torrents` 目录和 `dht_crawler.db` 数据库（WAL 模式）。
数据库记录种子 Hash、资源名、提供元数据的 peer 和发现时间；
`torrents` 目录按 Hash 保存 `.torrent` 文件。表结构与之前版本完全相同。

### 免责声明

本程序使用 libtorrent 构建和维护 DHT 节点。增加监听端口或并发任务数
可能显著提高 CPU、磁盘和网络开销，请自行评估流量和运行成本。
