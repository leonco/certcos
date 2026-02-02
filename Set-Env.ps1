# 设置 certcos 所需环境变量（仅当前 PowerShell 会话有效）
# 用法：先复制 env.example.ps1 为 env.local.ps1 并填入真实值，再执行: . .\Set-Env.ps1

$ErrorActionPreference = "Stop"
$scriptDir = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }

$envLocal = Join-Path $scriptDir "env.local.ps1"
if (-not (Test-Path $envLocal)) {
    Write-Host "未找到 env.local.ps1。请复制 env.example.ps1 为 env.local.ps1 并填入配置后重试。" -ForegroundColor Yellow
    Write-Host "  cp env.example.ps1 env.local.ps1" -ForegroundColor Gray
    exit 1
}

. $envLocal

$vars = @(
    @{ Name = "LEGO_COS_ENCRYPTION_KEY"; Value = $LEGO_COS_ENCRYPTION_KEY },
    @{ Name = "COS_BUCKET";               Value = $COS_BUCKET },
    @{ Name = "COS_REGION";               Value = $COS_REGION },
    @{ Name = "COS_APPID";                Value = $COS_APPID },
    @{ Name = "COS_SECRET_ID";            Value = $COS_SECRET_ID },
    @{ Name = "COS_SECRET_KEY";           Value = $COS_SECRET_KEY },
    @{ Name = "CF_DNS_API_TOKEN";         Value = $CF_DNS_API_TOKEN },
    @{ Name = "CLOUDFLARE_DNS_API_TOKEN"; Value = if ($CF_DNS_API_TOKEN) { $CF_DNS_API_TOKEN } else { $CLOUDFLARE_DNS_API_TOKEN } }
)

foreach ($e in $vars) {
    $val = $e.Value
    if ($e.Name -eq "CLOUDFLARE_DNS_API_TOKEN") {
        if ([string]::IsNullOrEmpty($val) -and $CF_DNS_API_TOKEN) { $val = $CF_DNS_API_TOKEN }
    }
    if (-not [string]::IsNullOrEmpty($val)) {
        Set-Item -Path "Env:$($e.Name)" -Value $val
    } elseif ($e.Name -ne "CLOUDFLARE_DNS_API_TOKEN") {
        Write-Host "警告: $($e.Name) 未设置，请检查 env.local.ps1" -ForegroundColor Yellow
    }
}

if (-not [string]::IsNullOrEmpty($LEGO_CA_DIR)) {
    Set-Item -Path "Env:LEGO_CA_DIR" -Value $LEGO_CA_DIR
}

Write-Host "环境变量已设置（当前会话有效）。可执行: .\certcos.exe cert -domain <域名> -email <邮箱>" -ForegroundColor Green
