package main

import (
	"crypto/rand"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/leonco/certcos/cmd"
	"github.com/leonco/certcos/cos"
	cryptopkg "github.com/leonco/certcos/crypto"
)

const usageHeader = `certcos：基于 ACME 的证书申请/续期，证书与加密私钥存于腾讯云 COS。

用法:
  certcos <命令> [选项]

命令:
  cert       申请或续期证书（需 -domain、-email）
  gen-key    生成 LEGO_COS_ENCRYPTION_KEY（Base64）
  sync-cert  将 COS 上的证书同步到腾讯云证书平台（需 -domain）

示例:
  certcos cert -domain example.com,www.example.com -email admin@example.com
  certcos gen-key
  certcos sync-cert -domain example.com
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageHeader)
		os.Exit(1)
	}
	sub := os.Args[1]
	switch sub {
	case "cert":
		runCert()
	case "gen-key", "genkey":
		runGenKey()
	case "sync-cert", "synccert":
		runSyncCert()
	case "-h", "--help", "help":
		fmt.Fprint(os.Stderr, usageHeader)
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", sub)
		fmt.Fprint(os.Stderr, usageHeader)
		os.Exit(1)
	}
}

func runCert() {
	fs := flag.NewFlagSet("cert", flag.ExitOnError)
	domain := fs.String("domain", "", "证书域名，多个用逗号分隔（如 example.com,www.example.com）")
	email := fs.String("email", "", "ACME 账户邮箱")
	fs.Parse(os.Args[2:])

	if *domain == "" || *email == "" {
		fmt.Fprintf(os.Stderr, "用法: %s cert -domain <域名[,域名,...]> -email <邮箱>\n", os.Args[0])
		fs.PrintDefaults()
		os.Exit(1)
	}
	domains := parseDomains(*domain)
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "至少需要一个非空域名")
		os.Exit(1)
	}

	encKeyB64 := os.Getenv("LEGO_COS_ENCRYPTION_KEY")
	if encKeyB64 == "" {
		fmt.Fprintln(os.Stderr, "需要设置 LEGO_COS_ENCRYPTION_KEY（32 字节密钥的 Base64）")
		os.Exit(1)
	}
	encKey, err := cryptopkg.KeyFromBase64(encKeyB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LEGO_COS_ENCRYPTION_KEY: %v\n", err)
		os.Exit(1)
	}

	cosBucket := os.Getenv("COS_BUCKET")
	cosRegion := os.Getenv("COS_REGION")
	cosAppID := os.Getenv("COS_APPID")
	cosSecretID := os.Getenv("COS_SECRET_ID")
	cosSecretKey := os.Getenv("COS_SECRET_KEY")
	if cosBucket == "" || cosRegion == "" || cosAppID == "" || cosSecretID == "" || cosSecretKey == "" {
		fmt.Fprintln(os.Stderr, "需要设置 COS_BUCKET, COS_REGION, COS_APPID, COS_SECRET_ID, COS_SECRET_KEY")
		os.Exit(1)
	}

	cfToken := os.Getenv("CF_DNS_API_TOKEN")
	if cfToken == "" {
		cfToken = os.Getenv("CLOUDFLARE_DNS_API_TOKEN")
	}
	if cfToken == "" {
		fmt.Fprintln(os.Stderr, "DNS-01 需要 CF_DNS_API_TOKEN 或 CLOUDFLARE_DNS_API_TOKEN")
		os.Exit(1)
	}
	if os.Getenv("CLOUDFLARE_DNS_API_TOKEN") == "" {
		os.Setenv("CLOUDFLARE_DNS_API_TOKEN", cfToken)
	}

	caDir := os.Getenv("LEGO_CA_DIR")
	if caDir == "" {
		caDir = "https://acme-v02.api.letsencrypt.org/directory"
	}

	cfg := cmd.Config{
		Domains: domains,
		Email:   *email,
		COS: cos.Config{
			Bucket:    cosBucket,
			Region:    cosRegion,
			AppID:     cosAppID,
			SecretID:  cosSecretID,
			SecretKey: cosSecretKey,
		},
		EncKey: encKey,
		CADir:  caDir,
	}

	if err := cmd.Run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func runGenKey() {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		fmt.Fprintf(os.Stderr, "gen-key: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(base64.StdEncoding.EncodeToString(b))
	fmt.Fprintln(os.Stderr, "将上述值填入 LEGO_COS_ENCRYPTION_KEY 环境变量")
}

func runSyncCert() {
	fs := flag.NewFlagSet("sync-cert", flag.ExitOnError)
	domain := fs.String("domain", "", "COS 存储键（一般为证书主域名）")
	fs.Parse(os.Args[2:])
	if *domain == "" {
		fmt.Fprintf(os.Stderr, "用法: %s sync-cert -domain <域名>\n", os.Args[0])
		fs.PrintDefaults()
		os.Exit(1)
	}
	encKeyB64 := os.Getenv("LEGO_COS_ENCRYPTION_KEY")
	if encKeyB64 == "" {
		fmt.Fprintln(os.Stderr, "需要设置 LEGO_COS_ENCRYPTION_KEY")
		os.Exit(1)
	}
	encKey, err := cryptopkg.KeyFromBase64(encKeyB64)
	if err != nil {
		fmt.Fprintf(os.Stderr, "LEGO_COS_ENCRYPTION_KEY: %v\n", err)
		os.Exit(1)
	}
	cosBucket := os.Getenv("COS_BUCKET")
	cosRegion := os.Getenv("COS_REGION")
	cosAppID := os.Getenv("COS_APPID")
	cosSecretID := os.Getenv("COS_SECRET_ID")
	cosSecretKey := os.Getenv("COS_SECRET_KEY")
	if cosBucket == "" || cosRegion == "" || cosAppID == "" || cosSecretID == "" || cosSecretKey == "" {
		fmt.Fprintln(os.Stderr, "需要设置 COS_BUCKET, COS_REGION, COS_APPID, COS_SECRET_ID, COS_SECRET_KEY")
		os.Exit(1)
	}
	resourceTypesRegions := parseResourceTypesRegions(os.Getenv("SYNC_CERT_RESOURCE_TYPES"))

	store, err := cos.NewStore(cos.Config{Bucket: cosBucket, Region: cosRegion, AppID: cosAppID, SecretID: cosSecretID, SecretKey: cosSecretKey})
	if err != nil {
		fmt.Fprintf(os.Stderr, "COS: %v\n", err)
		os.Exit(1)
	}
	if err := cmd.RunSyncCert(*domain, store, encKey, cosSecretID, cosSecretKey, resourceTypesRegions); err != nil {
		fmt.Fprintf(os.Stderr, "错误: %v\n", err)
		os.Exit(1)
	}
}

func parseDomains(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if d := strings.TrimSpace(p); d != "" {
			out = append(out, d)
		}
	}
	return out
}

func parseResourceTypesRegions(s string) map[string][]string {
	if s == "" {
		return nil
	}
	m := make(map[string][]string)
	for _, group := range strings.Split(s, ";") {
		rt, regions, _ := strings.Cut(group, ":")
		rt = strings.TrimSpace(rt)
		if rt == "" {
			continue
		}
		for _, r := range strings.Split(regions, ",") {
			if r = strings.TrimSpace(r); r != "" {
				m[rt] = append(m[rt], r)
			}
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}
