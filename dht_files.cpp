// dht_files: prints the file tree recorded in the file index for one or more
// info-hashes. Read-only, so it can run while the crawler writes the index.

#include "file_index.hpp"
#include "platform.hpp"

#include <exception>
#include <filesystem>
#include <string>
#include <vector>

namespace
{

void print_usage(const std::string &program)
{
    platform::write_stderr(
        "用法: " + program + " [选项] HASH [HASH...]\n\n"
        "按 info-hash（40 位十六进制）查询文件列表索引，以目录树输出文件名和大小。\n\n"
        "选项:\n"
        "  --index PATH   文件列表索引路径，默认 dht_files.db\n"
        "  --ascii        用 ASCII 字符绘制目录树\n"
        "  --bytes        显示精确字节数\n"
        "  --help         显示帮助\n\n"
        "退出码: 0 全部找到；1 有 Hash 无效或未找到；2 参数错误或无法读取索引\n");
}

} // namespace

int main(int argc, char **argv)
{
    const std::vector<std::string> arguments = platform::utf8_arguments(argc, argv);
    const std::string program = arguments.empty() ? "dht_files" : arguments.front();

    std::filesystem::path index_path = "dht_files.db";
    file_index::TreeOptions options;
    std::vector<std::string> hashes;
    for (std::size_t i = 1; i < arguments.size(); ++i)
    {
        const std::string &argument = arguments[i];
        if (argument == "--help")
        {
            print_usage(program);
            return 0;
        }
        if (argument == "--ascii")
            options.ascii = true;
        else if (argument == "--bytes")
            options.exact_sizes = true;
        else if (argument == "--index")
        {
            if (++i >= arguments.size())
            {
                print_usage(program);
                return 2;
            }
            index_path = platform::path_from_utf8(arguments[i]);
        }
        else if (!argument.empty() && argument[0] == '-')
        {
            print_usage(program);
            return 2;
        }
        else
        {
            hashes.push_back(argument);
        }
    }
    if (hashes.empty())
    {
        print_usage(program);
        return 2;
    }

    try
    {
        file_index::FileIndex index(index_path, file_index::FileIndex::Mode::read_only);
        int status = 0;
        bool first = true;
        for (const std::string &text : hashes)
        {
            const auto info_hash = file_index::parse_hash(text);
            if (!info_hash)
            {
                platform::write_stderr("无效的 info-hash: " + file_index::printable(text) + "\n");
                status = 1;
                continue;
            }
            const auto entry = index.get(*info_hash);
            if (!entry)
            {
                platform::write_stderr("未找到: " + file_index::to_hex(*info_hash) + "\n");
                status = 1;
                continue;
            }
            if (!first)
                platform::write_stdout("\n");
            first = false;
            platform::write_stdout(file_index::render_tree(*entry, options));
        }
        return status;
    }
    catch (const std::exception &error)
    {
        platform::write_stderr(std::string("错误: ") + error.what() + "\n");
        return 2;
    }
}
