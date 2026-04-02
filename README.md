# mac-bash-proxy-tunnel

一个基于 Node.js (>=20) 的加密代理隧道工具，包含 `service`（服务端）与 `client`（客户端）两个运行环境。

## 功能概览

- Service 端监听一个端口，负责 TCP/UDP 转发。
- Client 端连接 Service 后，在本机 `127.0.0.1:8890` 启动本地代理。
- 支持 HTTP Proxy 与 SOCKS5（CONNECT）代理模式。
- 使用 **RSA + AES-GCM** 建立加密通道（非对称密钥用于会话密钥交换）。
- 启动 `service` 时会输出公钥文本（PEM 和 base64），供客户端使用。
- 客户端首次连接时获取 token；服务端随机每 5/10/15 分钟轮换 token。
- 当 token 失效时，服务端返回 `token_invalid` 与新 token，客户端自动更新并继续后续请求。
- 客户端在发送后等待响应超过 90 秒会主动进行健康检查；连续 10 次仍无有效响应则终止等待并返回错误。
- service 端会记录客户端连接、鉴权成功/失败、转发错误和断开连接等日志，便于排障。

## 安装

```bash
npm install
```

## 启动 service

```bash
npm run service -- --port 7000 --save-pubkey ./pub.key
```

参数：
- `--port`：服务监听端口
- `--save-pubkey`：将公钥写入文件，便于 client 使用

> 注意：`npm run` 传参需要 `--`，例如 `npm run service -- --port 7000`

### 在 Docker 中运行 service

构建镜像：

```bash
docker build -t mac-bash-proxy-service .
```

运行容器（映射 7000 端口）：

```bash
docker run --rm -p 7000:7000 mac-bash-proxy-service
```

如果你希望把公钥保存到宿主机文件，可挂载卷并覆盖启动命令：

```bash
docker run --rm -p 7000:7000 -v "$(pwd):/data" \
  mac-bash-proxy-service \
  node src/service.js --port 7000 --save-pubkey /data/pub.key
```

## 启动 client

```bash
npm run client -- --address <service-ip-or-domain> --port 7000 --pubkey ./pub.key
```

参数：
- `--address`：service 地址
- `--port`：service 端口
- `--pubkey`：service 公钥文件路径
- `--local-port`：本地代理端口（可选，默认 `8890`）

## 配置 bash 代理

```bash
export https_proxy=http://127.0.0.1:8890
export http_proxy=http://127.0.0.1:8890
export all_proxy=socks5://127.0.0.1:8890
```

## 说明

- 本项目要求 Node.js 20+。
- 目前 SOCKS5 支持 CONNECT，不支持 IPv6 与 UDP ASSOC。
- UDP 转发能力在 service 侧已提供协议处理接口（`udp_request` / `udp_response`）。

## License

MIT
