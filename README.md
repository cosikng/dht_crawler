## 一个简单的dht爬虫

### 依赖库
```
libtorrent-rasterbar
libsqlite3
```
### 编译
`make`
### 执行
`./dht_db bind_addr threads`

`bind_addr`指定要绑定的接口，`IPv4`和`IPv6`均可

`threads`指定要启动的线程数，即DHT实例数，绑定的端口从`6881`开始，注意设置防火墙开放对应端口
### 结果查看
运行一段时间后同目录下会出现`tmp`、`torrents`两个目录和`dht_crawler.db`一个文件，`dht_crawler.db`是`sqlite`数据库文件，可以用`sqlite`终端或者`python`的`sqlite`库打开，记录了爬取到的种子哈希、资源名、提供该种子的peer和时间。`torrents`目录下则以哈希值为文件名存储所有种子

`TIPS`:如果尝试下载种子时找不到任何peer，可以添加数据库中记录的peer试一下

### 免责声明
本程序直接使用`libtorrent`库做DHT网络构建和维护，完全符合DHT协议规范，可以正常向外提供DHT节点服务，因此开启较多线程数时可能占用大量cpu和网络带宽，请自行对自己的流量和账单负责