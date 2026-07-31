# caddy-tunnel

`caddy-tunnel` 将仓库中的 `tunnel-server` 集成为 Caddy HTTP handler。它在 Caddy 启动时创建服务端 TUN 设备，并在匹配的请求上处理 tunnel HTTP 握手及其后的双向原始数据流。

> 此模块需要创建和删除 TUN 设备的系统权限；通常 Linux 上需要以 root 运行 Caddy 或授予相应的 `CAP_NET_ADMIN` 权限。一个 TUN 设备只能由一个实例使用。

## 构建

使用 [xcaddy](https://github.com/caddyserver/xcaddy) 构建带模块的 Caddy：

```sh
xcaddy build --with github.com/lyp256/gateway/caddy-tunnel=/path/to/gateway/caddy-tunnel
```

构建完成后可用 `./caddy list-modules | grep http.handlers.tunnel` 确认模块已加载。

## Caddyfile

将 `tunnel` 放在供 tunnel 客户端连接的路径上。建议只暴露给受信任的网络，并以 TLS 保护它：

```caddyfile
tunnel.example.com {
	@tunnel path /tunnel
	handle @tunnel {
		tunnel {
			device_name gateway-tun0
			mtu 1400
			cidr 198.18.18.0/24
		}
	}
}
```

指令语法：

```caddyfile
tunnel {
	device_name <name>
	mtu <1-65535>
	cidr <ipv4-prefix>
}
```

所有子指令都可省略，默认值与 `cmd/tunnel-server` 一致：`device_name tunnel-server`、`mtu 1500`、`cidr 198.18.18.0/24`。`cidr` 必须是至少拥有两个可分配 IPv4 地址的网段（例如 `/30` 或更宽）。

`tunnel` 是终止型 handler：成功接管请求后不会继续执行后续 Caddy handler。不要在同一条请求路径上配置会提前返回响应的 `respond`、`file_server` 或其他终止型 handler。

## JSON 配置

模块 ID 为 `http.handlers.tunnel`，字段为 `device_name`、`mtu` 和 `cidr`：

```json
{
  "handler": "tunnel",
  "device_name": "gateway-tun0",
  "mtu": 1400,
  "cidr": "198.18.18.0/24"
}
```

省略字段时会使用上述默认值。
