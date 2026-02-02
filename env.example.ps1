# certcos 环境变量模板
# 复制此文件为 env.local.ps1，填入真实值后执行: . .\Set-Env.ps1

# 加密私钥用的 32 字节密钥，Base64 编码（可用: [Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Maximum 256 }) -as [byte[]]) 生成）
$LEGO_COS_ENCRYPTION_KEY = "YOUR_32_BYTE_KEY_BASE64"

# 腾讯云 COS
$COS_BUCKET   = "your-bucket-name"
$COS_REGION   = "ap-guangzhou"
$COS_APPID    = "your-appid"
$COS_SECRET_ID  = "your-secret-id"
$COS_SECRET_KEY = "your-secret-key"

# Cloudflare DNS API Token（需 Zone:DNS Edit + Zone:Read）
$CF_DNS_API_TOKEN = "your-cloudflare-dns-api-token"

# 可选：ACME 目录，默认 Let's Encrypt 生产；测试可用 staging
# $LEGO_CA_DIR = "https://acme-staging-v02.api.letsencrypt.org/directory"
