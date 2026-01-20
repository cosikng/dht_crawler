#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <set>
#include <mutex>
#include <memory>
#include <atomic>

#include <libtorrent/session.hpp>
#include <libtorrent/session_params.hpp>
#include <libtorrent/settings_pack.hpp>
#include <libtorrent/alert_types.hpp>
#include <libtorrent/bdecode.hpp> // For bdecode_node
#include <libtorrent/entry.hpp>   // For create_torrent
#include <libtorrent/sha1_hash.hpp>
#include <libtorrent/hex.hpp> // for to_hex
#include <libtorrent/add_torrent_params.hpp>
#include <libtorrent/create_torrent.hpp>
#include <libtorrent/torrent_info.hpp>
#include <sqlite3.h>

class DatabaseManager
{
public:
    DatabaseManager(const char *db_file)
    {
        if (sqlite3_open(db_file, &db))
        {
            std::cerr << "数据库打开失败: " << sqlite3_errmsg(db) << std::endl;
            db = nullptr;
            return;
        }

        const char *sql_create_table =
            "CREATE TABLE IF NOT EXISTS torrents ("
            "info_hash TEXT PRIMARY KEY NOT NULL,"
            "name TEXT NOT NULL,"
            "discovered_peer TEXT NOT NULL,"
            "timestamp DATETIME DEFAULT CURRENT_TIMESTAMP"
            ");";

        char *err_msg = nullptr;
        if (sqlite3_exec(db, sql_create_table, 0, 0, &err_msg) != SQLITE_OK)
        {
            std::cerr << "建表失败: " << err_msg << std::endl;
            sqlite3_free(err_msg);
        }
    }

    ~DatabaseManager()
    {
        if (db)
        {
            sqlite3_close(db);
        }
    }

    void load_hashes(std::set<lt::sha1_hash> &hashes)
    {
        if (!db)
            return;

        const char *sql_select = "SELECT info_hash FROM torrents;";
        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(db, sql_select, -1, &stmt, 0) == SQLITE_OK)
        {
            while (sqlite3_step(stmt) == SQLITE_ROW)
            {
                const unsigned char *text = sqlite3_column_text(stmt, 0);
                if (text)
                {
                    std::string hash_hex = reinterpret_cast<const char *>(text);
                    if (hash_hex.length() == 40)
                    {
                        lt::sha1_hash hash;
                        // Manual hex to bytes to convert back to sha1_hash
                        for (size_t i = 0; i < 20; ++i)
                        {
                            std::string byteString = hash_hex.substr(i * 2, 2);
                            hash[i] = (char)strtol(byteString.c_str(), nullptr, 16);
                        }
                        hashes.insert(hash);
                    }
                }
            }
            sqlite3_finalize(stmt);
        }
    }

    void add_torrent(const std::string &hash, const std::string &name, const std::string &peer)
    {
        if (!db)
            return;

        // 使用互斥锁保证线程安全
        std::lock_guard<std::mutex> lock(db_mutex);

        const char *sql_insert = "INSERT OR IGNORE INTO torrents (info_hash, name, discovered_peer) VALUES (?, ?, ?);";
        sqlite3_stmt *stmt;

        if (sqlite3_prepare_v2(db, sql_insert, -1, &stmt, 0) == SQLITE_OK)
        {
            sqlite3_bind_text(stmt, 1, hash.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 2, name.c_str(), -1, SQLITE_STATIC);
            sqlite3_bind_text(stmt, 3, peer.c_str(), -1, SQLITE_STATIC);

            if (sqlite3_step(stmt) != SQLITE_DONE)
            {
                std::cerr << "数据插入失败: " << sqlite3_errmsg(db) << std::endl;
            }
            sqlite3_finalize(stmt);
        }
    }

private:
    sqlite3 *db = nullptr;
    std::mutex db_mutex;
};

// 全局资源保持不变
std::mutex g_seen_hashes_mutex;
std::set<lt::sha1_hash> g_seen_hashes;

char bind_address[500];

// 并发控制
std::atomic<int> g_active_tasks{0};
const int MAX_CONCURRENT_TASKS = 200; // 限制最大并发线程数

struct TaskCounter {
    TaskCounter() { g_active_tasks++; }
    ~TaskCounter() { g_active_tasks--; }
};

void fetch_metadata(lt::session &ses, lt::sha1_hash const &info_hash, lt::tcp::endpoint const &peer, DatabaseManager* db_manager)
{
    // 如果并发任务过多，直接放弃，避免 CPU 过载
    if (g_active_tasks >= MAX_CONCURRENT_TASKS)
        return;
    
    TaskCounter task_guard; // 自动管理计数

    std::string hex_hash = lt::aux::to_hex(info_hash.to_string());
    // std::cout << "[Fetcher] 启动任务: " << hex_hash << " from " << peer.address().to_string() << ":" << peer.port() << std::endl;

    lt::add_torrent_params params;
    params.info_hashes.v1 = info_hash;
    // 指定下载目录，例如 "torrents"
    params.save_path = "tmp";
    params.flags |= lt::torrent_flags::upload_mode;
    // params.flags |= lt::torrent_flags::stop_when_ready;

    lt::torrent_handle h = ses.add_torrent(params);
    if (!h.is_valid())
    {
        std::cerr << "[Fetcher] 错误: 添加种子失败 " << hex_hash << std::endl;
        return;
    }

    h.connect_peer(peer);

    for (int i = 0; i < 30; ++i)
    {
        if (h.status().has_metadata)
        {
            std::cout << "[Fetcher] 成功: " << hex_hash << std::endl;

            std::shared_ptr<const lt::torrent_info> ti;
            for (int j = 0; j < 5; ++j)
            { // 最多重试5次
                ti = h.torrent_file();
                if (ti)
                    break;                                                  // 如果成功获取，就跳出重试循环
                std::this_thread::sleep_for(std::chrono::milliseconds(50)); // 等待50毫秒再试
            }
            if (ti)
            {
                try
                {
                    lt::create_torrent ct(*ti);
                    auto const entry = ct.generate(); // 这里可能抛
                    std::vector<char> buffer;
                    lt::bencode(std::back_inserter(buffer), entry);

                    std::string filename = "torrents/" + hex_hash + ".torrent";
                    std::ofstream(filename, std::ios::binary).write(buffer.data(), buffer.size());

                    std::string peer_str = peer.address().to_string() + ":" + std::to_string(peer.port());
                    db_manager->add_torrent(hex_hash, ti->name(), peer_str);
                    std::cout << "[DB] 已将 " << ti->name() << " 存入数据库。" << std::endl;

                    // 检查并删除 tmp 目录下的残留，使用 system 命令以避免 filesystem 依赖
                    std::string safe_name = ti->name();
                    std::string escaped_name;
                    for (char c : safe_name)
                    {
                        if (c == '\'')
                            escaped_name += "'\\''";
                        else
                            escaped_name += c;
                    }
                    std::string cmd = "rm -rf 'tmp/" + escaped_name + "'";
                    system(cmd.c_str());
                    std::cout << "[Fetcher] 执行清理: " << cmd << std::endl;
                }
                catch (std::exception const &e)
                {
                    std::cerr << "[Fetcher] 生成 torrent 文件失败: " << e.what() << " hash=" << hex_hash << std::endl;
                }
            }
            else
            {
                std::cerr << "[Fetcher] 错误: 无法获取 torrent_info " << hex_hash << std::endl;
            }

            // 使用 delete_files 标志清理下载目录
            ses.remove_torrent(h, lt::session::delete_files);
            return;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cerr << "[Fetcher] 超时: " << hex_hash << std::endl;
    // *** FIX for 2.0.x ***: 使用顶层命名空间的 remove_flags_t
    ses.remove_torrent(h, lt::session::delete_files);
}

DatabaseManager* db_manager_global = nullptr;

void DHTListener(int id)
{
    unsigned long long requests = 0, responses = 0;
    lt::settings_pack settings;
    settings.set_int(lt::settings_pack::alert_mask, lt::alert_category::dht | lt::alert_category::status | lt::alert_category::dht_log);
    settings.set_bool(lt::settings_pack::enable_dht, true);
    settings.set_bool(lt::settings_pack::enable_lsd, false);
    // settings.set_bool(lt::settings_pack::enable_pex, false);

    settings.set_str(lt::settings_pack::dht_bootstrap_nodes,
                     "dht.libtorrent.org:25401,router.utorrent.com:6881,dht.transmissionbt.com:6881,router.bittorrent.com:6881");
    char addr[50];
    sprintf(addr, "%s:%d", bind_address, 6881 + id);
    settings.set_str(lt::settings_pack::listen_interfaces, addr);

    lt::session ses(settings);
    system("mkdir -p torrents");
    system("mkdir -p tmp");
    std::cout << "DHT 爬虫已启动 (libtorrent 2.0.x)，正在监听网络..." << std::endl;

    // *** NEW: 初始化计时器 ***
    auto last_stats_time = std::chrono::steady_clock::now();
    const auto stats_interval = std::chrono::seconds(60); // 每10秒显示一次状态

    std::cout << "DHT 爬虫已启动，数据库已连接..." << std::endl;

    while (true)
    {
        std::vector<lt::alert *> alerts;
        ses.pop_alerts(&alerts);

        for (lt::alert *a : alerts)
        {
            if (auto *live = lt::alert_cast<lt::dht_live_nodes_alert>(a))
            {
                std::cout << id << ":[Stats] Nodes: " << live->num_nodes() 
                          << " Req: " << requests 
                          << " Resp: " << responses
                          << " ActiveTasks: " << g_active_tasks.load() 
                          << std::endl;
            }
            else if (auto *stat = lt::alert_cast<lt::dht_stats_alert>(a))
            {
                ses.dht_live_nodes(stat->nid);
            }
            else if (auto *p = lt::alert_cast<lt::dht_pkt_alert>(a))
            {
                // 性能优化：只处理入站包，忽略出站包
                if (p->direction != lt::dht_pkt_alert::incoming)
                    continue;

                lt::error_code ec;
                try
                {
                    // std::cout<<"收到消息\n";

                    // *** FIX for 2.0.x ***: 使用 bdecode_node 并直接传递 packet_buf()
                    lt::bdecode_node dict = lt::bdecode(p->pkt_buf(), ec);
                    if (ec)
                        continue;

                    // 使用 bdecode_node 的 API 进行遍历
                    if (dict.type() == lt::bdecode_node::dict_t && dict.dict_find_string_value("y") == "q")
                    {
                        if (dict.dict_find_string_value("q") == "announce_peer")
                        {
                            lt::bdecode_node args = dict.dict_find("a");
                            if (args.type() != lt::bdecode_node::dict_t)
                                continue;

                            lt::bdecode_node hash_entry = args.dict_find("info_hash");
                            if (hash_entry.type() != lt::bdecode_node::string_t)
                                continue;

                            // *** FIX for 2.0.x ***: 使用 string_view() 构造哈希，避免弃用警告
                            lt::sha1_hash info_hash(hash_entry.string_value());

                            std::unique_lock<std::mutex> lock(g_seen_hashes_mutex);
                            if (g_seen_hashes.find(info_hash) == g_seen_hashes.end())
                            {
                                g_seen_hashes.insert(info_hash);
                                lock.unlock();

                                std::string hex_hash = lt::aux::to_hex(info_hash.to_string());
                                std::cout << id << "[Listener] 发现新 announce_peer: " << hex_hash << std::endl;

                                // 使用 dict_find_int_value 获取端口
                                long long port_val = args.dict_find_int_value("port");
                                if (port_val <= 0 || port_val > 65535)
                                    continue;

                                // *** FIX for 2.0.x ***: 使用 get_endpoint() 成员函数
                                lt::tcp::endpoint peer(p->node.address(), static_cast<std::uint16_t>(port_val));

                                std::thread(fetch_metadata, std::ref(ses), info_hash, peer, db_manager_global).detach();
                            }
                        }
                        else if (dict.dict_find_string_value("q") == "get_peers")
                        {
                            // std::cout << "[Listener] 收到 get_peers 请求" << std::endl;
                        }
                        else if (dict.dict_find_string_value("q") == "find_node")
                        {
                            // std::cout << "[Listener] 收到 find_node 请求" << std::endl;
                        }
                        else if (dict.dict_find_string_value("q") == "ping")
                        {
                            // std::cout << "[Listener] 收到 ping 请求" << std::endl;
                        }
                        else
                        {
                            std::cout << id << "[Listener] 收到未知请求: " << dict.dict_find_string_value("q") << std::endl;
                        }
                        ++requests;
                    }
                    else
                    {
                        ++responses;
                    }
                }
                catch (const std::exception &e)
                {
                    std::cerr << id << "[Listener] 处理请求时发生异常: " << e.what() << std::endl;
                }
            }

            // *** NEW: 检查是否到了显示统计信息的时间 ***
            auto const now = std::chrono::steady_clock::now();
            if (now - last_stats_time > stats_interval)
            {
                // 请求dht状态
                ses.post_dht_stats();
                // 重置计时器
                last_stats_time = now;
            }

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
    }
    return;
}

int main(int argc, char *argv[])
{
    // 初始化时加载已有 hash
    {
        db_manager_global = new DatabaseManager("dht_crawler.db");
        db_manager_global->load_hashes(g_seen_hashes);
        std::cout << "已从数据库加载 " << g_seen_hashes.size() << " 个历史 Hash。" << std::endl;
    }

    int num = 1;
    if (argc == 3)
    {
        num = atoi(argv[2]);
        std::strcpy(bind_address, argv[1]);
    }
    else if(argc == 2)
    {
        std::strcpy(bind_address, argv[1]);
    }
    else{
        std::strcpy(bind_address, "0.0.0.0");
    }
    std::cout << "绑定地址: " << bind_address << std::endl;
    while (num--)
    {
        std::thread(DHTListener, num).detach();
    }
    while (true)
    {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}