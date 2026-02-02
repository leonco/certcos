# certcos

基于 [go-acme/lego](https://github.com/go-acme/lego) 的 SSL 证书自动申请与续期工具。证书与账户数据存储在腾讯云 COS，私钥经 AES-256-GCM 加密后存放；验证方式为 DNS-01，DNS 服务使用 Cloudflare。

## 功能

- **cert**：根据 COS 上已有文件自动判断新建/复用 ACME 账户、新申请或续期证书；参数 `-domain`（可逗号分隔多个）、`-email`，其余配置通过环境变量传入
- **gen-key**：生成随机 32 字节 Base64 密钥，用于 `LEGO_COS_ENCRYPTION_KEY`
- **sync-cert**：将 COS 上的证书与腾讯云 SSL 证书平台对比并上传（若平台无证书或更旧）
- 私钥（账户私钥、域名证书私钥）加密存储，证书明文存储

## 环境变量

| 用途 | 变量名 | 说明 |
|------|--------|------|
| Cloudflare | `CF_DNS_API_TOKEN` 或 `CLOUDFLARE_DNS_API_TOKEN` | DNS API Token（需 Zone:DNS Edit + Zone:Read） |
| COS | `COS_BUCKET` | 存储桶名称（不含 appid 后缀） |
| COS | `COS_REGION` | 地域，如 `ap-guangzhou` |
| COS | `COS_APPID` | 腾讯云账号 APPID |
| COS | `COS_SECRET_ID` | 密钥 SecretId |
| COS | `COS_SECRET_KEY` | 密钥 SecretKey |
| 加密 | `LEGO_COS_ENCRYPTION_KEY` | 32 字节密钥的 Base64，用于 AES-256-GCM 加密私钥 |

可选：

- `LEGO_CA_DIR`：ACME 目录 URL，默认 Let's Encrypt 生产环境；测试可用 `https://acme-staging-v02.api.letsencrypt.org/directory`

### 用 PowerShell 设置环境变量

1. 生成加密密钥并复制模板：
   ```powershell
   .\certcos.exe gen-key   # 输出一行 Base64，复制到 env.local.ps1 的 LEGO_COS_ENCRYPTION_KEY
   Copy-Item env.example.ps1 env.local.ps1
   # 编辑 env.local.ps1，填入上述密钥及 COS、Cloudflare 等
   ```
2. 在当前会话加载环境变量后运行工具：
   ```powershell
   . .\Set-Env.ps1
   .\certcos.exe cert -domain qianqiu.ren,*.qianqiu.ren -email admin@example.com
   ```
   `env.local.ps1` 已加入 `.gitignore`，不会提交到仓库。

## 使用

所有操作均通过子命令执行；无参数或 `certcos help` 可查看命令列表。

```bash
# 申请或续期证书（单个域名）
certcos cert -domain example.com -email admin@example.com

# 多个域名共一张证书（逗号分隔，含通配符）
certcos cert -domain qianqiu.ren,*.qianqiu.ren -email admin@example.com

# 生成加密密钥（填入 LEGO_COS_ENCRYPTION_KEY）
certcos gen-key

# 将 COS 证书同步到腾讯云证书平台
certcos sync-cert -domain qianqiu.ren
```

确保已设置上述环境变量。`cert` 首次运行会创建 ACME 账户并申请证书；之后运行会按证书有效期自动续期（默认在到期前 30 天内续期）。证书按第一个域名的路径存于 COS（如 `certs/qianqiu_ren/`）。`sync-cert` 的 `-domain` 为存储路径对应的主域名（即申请时第一个域名），平台侧以该域名作为证书备注（Alias）匹配。

## COS 路径约定

- **账户**：`account/<sanitized_email>/private_key.enc`、`account/<sanitized_email>/registration.json`
- **证书**：`certs/<sanitized_domain>/cert.pem`、`certs/<sanitized_domain>/key.enc`、`certs/<sanitized_domain>/issuer.pem`、`certs/<sanitized_domain>/resource.json`

其中 `sanitized_email` / `sanitized_domain` 将 `@`、`.` 等替换为 `_`，保证路径合法且唯一。

## 加密与密钥

- **算法**：AES-256-GCM，nonce 12 字节随机，与密文一起存储
- **密钥**：从 `LEGO_COS_ENCRYPTION_KEY` Base64 解码得到 32 字节；丢失则无法解密已有私钥，请妥善备份并考虑轮换策略

## 权限建议

- **Cloudflare**：域名已在 Cloudflare 托管 DNS；Token 仅需 Zone:Read 与 DNS:Edit 权限
- **COS**：存储桶对该工具使用的 SecretId/SecretKey 具备读写对象权限即可

## 构建

```bash
go build -o certcos .
```

## 许可

MIT
