# 崩溃与并发问题记录

本文记录 2026-07-21 根据生产环境 core dump、当前代码和 libtorrent
版本检查得到的新问题。本文不表示这些问题已经修复；除特别注明外，条目均为待处理项。

优先级定义：

- `P0`：可能导致越界访问、段错误、进程异常终止或核心数据竞争
- `P1`：可能导致重复任务、状态不一致、数据丢失或长期阻塞
- `P2`：主要影响过载行为、性能、诊断能力或可维护性

## 已确认的 libtorrent Hash 越界崩溃

### 现象

程序运行一段时间后收到 `SIGSEGV`，core dump 的主要调用栈如下：

```text
libtorrent::create_torrent::set_hash2(...)
libtorrent::create_torrent::create_torrent(torrent_info const&)
CrawlerApp::write_torrent_file(...) at dht_db.cpp:925
CrawlerApp::handle_metadata(...) at dht_db.cpp:893
```

触发时正在保存的 info hash 为：

```text
4f2adba1291fbb09aefd92b3e3169b513b1ee0b2
```

生产环境确认使用 `libtorrent-rasterbar 2.0.5`。

### 原因判断

当前代码在收到 `metadata_received_alert` 后，通过
`torrent_handle::torrent_file()` 取得 `torrent_info`，随后调用：

```cpp
lt::create_torrent torrent(torrent_info);
```

libtorrent 会在这个构造过程中复制 v2/hybrid torrent 的 SHA-256 piece
hash，并调用 `create_torrent::set_hash2()`。2.0.5 对异常 `piece layers` 的
长度、边界和一致性校验不足。畸形或恶意元数据可能使 piece 下标超过内部
数组范围；Release 构建中的断言不能阻止越界访问，最终触发段错误。

该崩溃发生在 libtorrent 内部，不是 C++ 异常，因此当前 `try/catch` 无法捕获。
从调用栈和版本信息看，这是本次崩溃的首要原因，不属于多 session 共享状态问题。

### 库升级处理

libtorrent 2.0.9 加强了加载 v2 `piece layers` 以及 v1/v2 hash 一致性时的
校验。对于本次已知触发路径，最低目标版本应为 `2.0.9`，部署时优先使用
发行版能够稳定提供的更新 2.0.x 版本。

升级后的预期行为：

- 异常元数据在解析阶段被拒绝时，libtorrent 可能产生
  `metadata_failed_alert` 并自行重试。
- 当前程序尚未显式处理 `metadata_failed_alert`，因此对应任务可能继续占用
  active 槽位，直到 metadata timeout 后由 `expire_tasks()` 标记失败并移除。
- 如果异常以 `std::exception` 从 `create_torrent()` 或 `generate()` 抛出，
  `handle_metadata()` 会捕获异常、标记任务失败并移除 torrent。
- 如果产生 `torrent_error_alert`，当前程序会立即调用 `fail_task()`。

单纯升级到 2.0.9+ 预计可以避免本次 `set_hash2()` 越界崩溃，但不能修复本文
后续列出的应用层并发问题。

### 升级待办

- [ ] 将运行环境和开发包从 libtorrent 2.0.5 升级到至少 2.0.9。
- [ ] 清理旧构建目录后重新执行 CMake 配置和完整编译，避免头文件与动态库混用。
- [ ] 将 `CMakeLists.txt` 中 Config package 和 pkg-config fallback 的最低版本
  同时提高到 2.0.9；当前两条路径都只要求 2.0。
- [ ] 部署后分别检查 `pkg-config --modversion libtorrent-rasterbar` 和
  `ldd ./dht_db`，确认编译及运行时实际使用的新库。
- [ ] 显式处理 `metadata_failed_alert`，立即释放失败任务并记录错误原因，避免等待超时。
- [ ] 评估在应用层增加 v2 piece-layer 长度校验，作为第三方库之外的防御层。
- [ ] 评估用 libtorrent 推荐的 resume-data/`write_torrent_file_buf()` 流程替代
  `create_torrent(torrent_info)` 重建 torrent 文件。

## 并发与一致性问题

### P0：共享 SQLite 查询对象被并发访问

- [ ] `DatabaseManager::contains()` 被所有 session 线程调用，但所有线程共享同一个
  `DatabaseConnection reader_` 和同一个 `Statement contains_statement_`。
- [ ] 多个线程可能同时对同一个 `sqlite3_stmt*` 执行 `reset`、`bind` 和 `step`。
- [ ] 即使 SQLite 库本身以 serialized 模式构建，共享 prepared statement 的这一组
  操作也不是一个原子查询，参数和执行状态会互相覆盖。
- [ ] 后果包括错误查询结果、SQLite misuse、内部状态破坏，以及潜在的段错误。
- [ ] 修复方向：为每个 session 提供独立只读 connection/statement，或至少用专用
  mutex 包围完整的 `reset + bind + step` 查询周期。

### P0：跨 session 的 Hash 注册不是原子操作

- [ ] `hash_states` 和 `active_tasks` 都属于单个 `SessionContext`，不同 session 不共享
  正在处理的 Hash 状态。
- [ ] 两个 session 可同时收到同一 Hash，分别通过本 session 的状态检查。
- [ ] `database_.contains(hash)` 与随后向 `hash_states`/`active_tasks` 注册任务之间没有
  全局原子性；两个查询都可能在数据库写入前返回不存在。
- [ ] 后果是同一 Hash 被多个 session 同时 `add_torrent()`、连接 peer 和下载元数据，
  增加连接、DHT 查询、内存和 CPU 消耗。
- [ ] 修复方向：增加跨 session 的全局 Hash claim 状态机，使 checking、active、
  persisting、completed 和 failed/retry 的转换在同一协调器中完成。

### P0：同一 Hash 的 torrent 临时文件存在写入竞争

- [ ] `write_torrent_file()` 先检查最终文件是否存在，再统一写入
  `<hash>.torrent.tmp`，检查与创建不是原子操作。
- [ ] 跨 session 重复任务可能同时以 trunc 模式打开同一个临时文件，互相覆盖内容。
- [ ] 一个线程可能 rename 或删除另一个线程仍在写入/准备发布的临时文件。
- [ ] 后果包括损坏的 torrent 文件、rename 失败、文件存在但数据库状态失败，以及任务
  状态彼此不一致。
- [ ] 修复方向：先实现全局 Hash claim；文件层仍应使用每次写入唯一的临时文件名，
  并正确处理最终文件已被其他任务发布的情况。

### P0：数据库写线程异常时可能遗留无结果的 future

- [ ] `writer_loop()` 从队列取出本地 `batch` 后，如果在 `execute_batch()` 之外发生异常，
  外层 catch 只会失败队列中尚未取出的请求。
- [ ] 当前 batch 中尚未 `set_value()` 的 promise 析构后，对应 future 会进入
  broken-promise 状态。
- [ ] `poll_database_writes()` 调用 `future::get()` 时可能抛出 `std::future_error`；该调用
  位于 session 主循环中，不在 alert 的 `try/catch` 内。
- [ ] 未捕获异常会逃出 `run_session()` 线程入口并触发 `std::terminate()`。
- [ ] 修复方向：确保每个已出队请求无论成功、失败或异常都完成 promise，并在
  `poll_database_writes()` 与 session 线程入口设置异常边界。

### P1：数据库唯一约束只能消除重复记录，不能消除重复工作

- [ ] writer 使用 `INSERT OR IGNORE`，因此最终数据库通常只保留一条相同 Hash 记录。
- [ ] 唯一约束发生在元数据下载和文件生成之后，无法阻止前面的重复网络任务和文件竞争。
- [ ] 不同 session 对同一 Hash 的内存状态可能分别处于 active、persisting、completed
  或 failed，与数据库最终状态不同步。
- [ ] 修复方向：数据库唯一约束继续作为最终兜底，但不能替代全局 Hash claim。

### P1：数据库写入等待没有期限和容量限制

- [ ] `DatabaseManager::queue_` 没有最大长度，`pending_writes` 也没有超时或数量上限。
- [ ] 当数据库持续慢于 metadata 获取速度时，请求和 future 会持续积压并增加内存占用。
- [ ] 已完成元数据的 Hash 长期停留在 persisting 状态；当前仅在每个 session 内阻止重复，
  其他 session 仍可能再次下载同一 Hash。
- [ ] 修复方向：设置有界写队列、高低水位和写入超时；达到上限时暂停接收新 metadata
  任务或降低每 session active 上限。

### P1：并发上限是每 session 上限，不是进程总上限

- [ ] `context.active_tasks.size() >= config_.max_active` 只限制单个 session。
- [ ] 进程理论最大 active 数为 `listeners * max_active`，增加监听端口会线性放大 peer
  连接、metadata 内存、alert 和数据库写入压力。
- [ ] 这不是数据竞争，但会放大前述队列积压、重复任务和网络过载问题。
- [ ] 修复方向：同时保留每 session 配额和进程级总配额，并让数据库/文件写入压力参与
  是否接受新任务的决策。

### P1：session 线程入口缺少完整异常边界

- [ ] `drain_session()` 只捕获单个 alert 处理中的异常。
- [ ] `wait_for_alert()`、`expire_tasks()`、`poll_database_writes()`、
  `expire_hash_states()` 和统计调用抛出的异常会直接逃出线程入口。
- [ ] C++ 线程函数抛出未捕获异常会调用 `std::terminate()`，表现为进程突然退出，通常
  不是段错误但同样会造成长期运行稳定性问题。
- [ ] 修复方向：在 `run_session()` 最外层增加异常边界，并确保退出前清理本 session
  的 active torrents。

### P2：日志输出存在跨线程交错和同步 I/O 竞争

- [ ] 多个 session 线程和数据库写线程直接写入 `std::cout`/`std::cerr`。
- [ ] 日志片段可能交错，core 前后的关键上下文难以还原；高流量时还会竞争标准流锁并
  阻塞 session 线程。
- [ ] 修复方向：使用带 session/hash 字段的线程安全日志队列，或至少对完整日志行统一
  加锁并增加采样、限速和级别控制。

### P2：`metadata_failed_alert` 未形成及时的一致状态转换

- [ ] alert mask 已包含 error 类别，但 `handle_alert()` 没有处理
  `metadata_failed_alert`。
- [ ] libtorrent 会自动重试损坏或 hash 不匹配的 metadata，应用层任务状态仍保持 active。
- [ ] 任务最终可由 timeout 清理，因此不是永久泄漏，但会延迟释放 active 配额并减少
  有效 Hash 的抓取能力。
- [ ] 修复方向：收到该 alert 时记录 error，调用 `fail_task()`，并按统一 retry policy
  决定何时允许该 Hash 再次提交。

## 当前未发现的共享问题

以下对象目前由各自 session 线程独占，未发现直接的跨线程容器访问：

- 每个 `SessionContext` 的 `active_tasks`、`hash_states`、`pending_writes` 和统计计数。
- 每个监听端口对应的 `lt::session` 及其 alert 消费。
- 主线程只在所有 session 线程 join 后清理剩余 torrent，不与 session 循环并发操作。

这些结论不改变全局数据库、全局 Hash 协调和共享文件路径方面的问题。

## 建议处理顺序

1. 升级 libtorrent 到 2.0.9+，同步提高 CMake 最低版本并进行干净重编译。
2. 修复共享 SQLite reader/statement 的并发访问。
3. 引入进程级 Hash claim，统一跨 session 的任务状态和重试状态。
4. 修复 torrent 临时文件发布竞争。
5. 保证数据库 batch 中每个 promise 都会完成，并补齐 session 线程异常边界。
6. 增加数据库队列反压、进程级并发配额和 `metadata_failed_alert` 处理。
7. 最后完善日志串行化、异常元数据诊断和长期压力测试。
