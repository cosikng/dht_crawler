#include "torrent_file_list.hpp"

#include <algorithm>
#include <string>
#include <string_view>

#include <libtorrent/bdecode.hpp>

namespace lt = libtorrent;

namespace
{

// lt::string_view is boost::string_view in libtorrent 2.0 and
// std::string_view in 2.1.
std::string_view view(lt::string_view text)
{
    return std::string_view(text.data(), text.size());
}

// A recorded component as one path element.
void append_component(std::string &path, std::string_view component)
{
    if (component.empty())
        return;
    if (!path.empty())
        path.push_back('/');
    const std::size_t start = path.size();
    path.append(component);
    std::replace(path.begin() + static_cast<std::ptrdiff_t>(start), path.end(), '/', '_');
}

std::string_view string_value(const lt::bdecode_node &dict, const char *utf8_key, const char *key)
{
    const lt::bdecode_node preferred = dict.dict_find_string(utf8_key);
    if (preferred)
        return view(preferred.string_value());
    return view(dict.dict_find_string_value(key));
}

bool is_padding(const lt::bdecode_node &file, const lt::bdecode_node &path)
{
    if (view(file.dict_find_string_value("attr")).find('p') != std::string_view::npos)
        return true;
    // Older BitComet padding files carry no attr, only this name.
    for (int i = 0; i < path.list_size(); ++i)
    {
        if (view(path.list_string_value_at(i)).substr(0, 17) == "_____padding_file")
            return true;
    }
    return false;
}

} // namespace

std::optional<file_index::Entry> file_list_from_info(
    const file_index::InfoHash &info_hash,
    lt::span<char const> info_section)
{
    lt::error_code error;
    const lt::bdecode_node info = lt::bdecode(info_section, error);
    if (error || info.type() != lt::bdecode_node::dict_t)
        return std::nullopt;

    file_index::Entry entry;
    entry.info_hash = info_hash;
    append_component(entry.name, string_value(info, "name.utf-8", "name"));
    if (entry.name.empty())
        return std::nullopt;

    const lt::bdecode_node files = info.dict_find_list("files");
    if (!files)
    {
        const lt::bdecode_node length = info.dict_find_int("length");
        if (!length || length.int_value() < 0)
            return std::nullopt;
        entry.files.push_back(file_index::File{entry.name, static_cast<std::uint64_t>(length.int_value())});
        return entry;
    }

    for (int i = 0; i < files.list_size(); ++i)
    {
        const lt::bdecode_node file = files.list_at(i);
        if (file.type() != lt::bdecode_node::dict_t)
            continue;
        const lt::bdecode_node length = file.dict_find_int("length");
        lt::bdecode_node path = file.dict_find_list("path.utf-8");
        if (!path || path.list_size() == 0)
            path = file.dict_find_list("path");
        if (!length || length.int_value() < 0 || !path || is_padding(file, path))
            continue;

        std::string full = entry.name;
        for (int c = 0; c < path.list_size(); ++c)
        {
            if (path.list_at(c).type() == lt::bdecode_node::string_t)
                append_component(full, view(path.list_string_value_at(c)));
        }
        if (full.size() == entry.name.size())
            continue;
        entry.files.push_back(file_index::File{std::move(full), static_cast<std::uint64_t>(length.int_value())});
    }
    return entry;
}
