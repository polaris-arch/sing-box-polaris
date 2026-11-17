!!! quote "sing-box 1.14.0 中的更改"

    :material-plus: [http_client](#http_client)  
    :material-delete-clock: [download_detour](#download_detour)  
    :material-alert: [tag](#tag)  
    :material-plus: [initial_path](#initial_path)

!!! quote "sing-box 1.10.0 中的更改"

    :material-plus: `type: inline`

# 规则集

!!! question "自 sing-box 1.8.0 起"

### 结构

=== "内联"

    !!! question "自 sing-box 1.10.0 起"

    ```json
    {
      "type": "inline", // 可选
      "tag": "",
      "rules": []
    }
    ```

=== "本地文件"

    ```json
    {
      "type": "local",
      "tag": "", // 或 []
      "format": "source", // or binary
      "path": ""
    }
    ```

=== "远程文件"

    !!! info ""
    
        远程规则集将被缓存如果 `experimental.cache_file.enabled` 已启用。

    ```json
    {
      "type": "remote",
      "tag": "", // 或 []
      "format": "source", // or binary
      "url": "",
      "initial_path": "",
      "http_client": "", // 或 {}
      "update_interval": "",

      // 废弃的

      "download_detour": ""
    }
    ```

### 字段

#### type

==必填==

规则集类型， `local` 或 `remote`。

#### tag

==必填==

规则集的标签。

!!! question "自 sing-box 1.14.0 起"

    `tag` 也接受一组标签，用于一次定义多个共享其他选项的规则集。

    `path`、`url` 或 `initial_path` 中的 `{tag}` 占位符将被替换为每个标签，设置多个标签时必填。

    多个标签与 `type: inline` 冲突。

### 内联字段

!!! question "自 sing-box 1.10.0 起"

#### rules

==必填==

一组 [无头规则](./headless-rule/).

### 本地或远程字段

#### format

==必填==

规则集格式， `source` 或 `binary`。

当 `path` 或 `url` 使用 `json` 或 `srs` 作为扩展名时可选。

### 本地字段

#### path

==必填==

!!! note ""

    自 sing-box 1.10.0 起，文件更改时将自动重新加载。

规则集的文件路径。

### 远程字段

#### url

==必填==

规则集的下载 URL。

#### initial_path

!!! question "自 sing-box 1.14.0 起"

规则集初始内容的文件路径。

在启动时没有可用的规则集缓存时使用。

#### http_client

!!! question "自 sing-box 1.14.0 起"

用于下载规则集的 HTTP 客户端。

参阅 [HTTP 客户端字段](/zh/configuration/shared/http-client/) 了解详情。

留空时使用默认 HTTP 客户端：即由 [`default_http_client`](/zh/configuration/route/#default_http_client)
指定的客户端，或当 `default_http_client` 为空时使用顶级 `http_clients` 的第一项。

!!! failure "隐式默认已在 sing-box 1.14.0 废弃"

    当 `http_clients` 与 `default_http_client` 均未配置时，将使用通过默认出站连接的隐式 HTTP 客户端。
    该隐式默认已在 sing-box 1.14.0 废弃，并将在 sing-box 1.16.0 移除；请改为定义 `http_clients`。

#### update_interval

规则集的更新间隔。

默认使用 `1d`。

#### download_detour

!!! failure "已在 sing-box 1.14.0 废弃"

    `download_detour` 已在 sing-box 1.14.0 废弃且将在 sing-box 1.16.0 中被移除，请使用 `http_client` 代替。

用于下载规则集的出站的标签。

### resource_limits

本地和远程规则文件可指定单次加载的资源接纳上限。省略对象或单项为零时使用有限默认值：

```json
{
  "resource_limits": {
    "input_bytes": 67108864,
    "decoded_bytes": 268435456,
    "rules": 100000,
    "entries": 4000000,
    "string_bytes": 1048576
  }
}
```

`input_bytes` 限制 source 和 binary 的完整下载或文件大小，包括容器尾部。
其余字段用于二进制 SRS：解压字节、累计规则数（含逻辑子规则）、累计字段/列表/IP 区间条目、单字符串字节。
域名匹配器内部存储由解压字节限额约束；这些不是进程 RSS 或执行时长的硬上限。
二进制恢复/反编译在生成域名字符串或 IP 前缀列表前还会检查展开预算。
IP 恢复按每个前缀 128 个预算单位保守核算（包括临时结构）；相邻区间可能合并并实际使用更少。内部 mmap 缓存采用独立存储合同，不属于 SRS 流限额。

线格式不变。超限返回错误，不截断输入；重载失败保留已发布规则。
可信大文件可显式调高单项限制，但会增加资源暴露，不应对不可信下载设置近似无限的值。
需要非默认额度的可信 Go 工具可使用 `ReadContextWithLimits`。
