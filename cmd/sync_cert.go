package cmd

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/leonco/certcos/cos"
	cryptopkg "github.com/leonco/certcos/crypto"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	tcssl "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/ssl/v20191205"
)

// RunSyncCert loads cert from COS (decrypts private key), compares with Tencent SSL Certificate Platform,
// and uploads/updates if platform has no cert or an older one. -domain is the storage key (first domain).
func RunSyncCert(domain string, store *cos.Store, encKey []byte, secretID, secretKey string) error {
	ctx := context.Background()
	storageKey := domain

	certPem, err := store.Get(ctx, cos.CertPath(storageKey))
	if err != nil {
		return fmt.Errorf("get cert from COS: %w", err)
	}
	if len(certPem) == 0 {
		return fmt.Errorf("no certificate on COS for domain %s", storageKey)
	}
	keyEnc, err := store.Get(ctx, cos.CertKeyPath(storageKey))
	if err != nil {
		return fmt.Errorf("get key from COS: %w", err)
	}
	if len(keyEnc) == 0 {
		return fmt.Errorf("no private key on COS for domain %s", storageKey)
	}
	keyPem, err := cryptopkg.Decrypt(encKey, keyEnc)
	if err != nil {
		return fmt.Errorf("decrypt private key: %w", err)
	}

	// Parse COS cert to get NotAfter
	block, _ := pem.Decode(certPem)
	if block == nil {
		return fmt.Errorf("invalid cert PEM on COS")
	}
	cosCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse COS cert: %w", err)
	}
	cosNotAfter := cosCert.NotAfter

	// Tencent SSL client (SSL API does not require region; use empty or ap-guangzhou)
	cred := common.NewCredential(secretID, secretKey)
	client, err := tcssl.NewClient(cred, "", profile.NewClientProfile())
	if err != nil {
		return fmt.Errorf("tencent ssl client: %w", err)
	}

	// List certificates and find one matching this domain (by Alias = storageKey)
	req := tcssl.NewDescribeCertificatesRequest()
	req.SearchKey = common.StringPtr(storageKey)
	var platformNotAfter *time.Time
	var totalCount uint64
	for offset := uint64(0); ; {
		req.Offset = common.Uint64Ptr(offset)
		req.Limit = common.Uint64Ptr(100)
		resp, err := client.DescribeCertificates(req)
		if err != nil {
			return fmt.Errorf("describe certificates: %w", err)
		}
		if resp.Response.TotalCount != nil {
			totalCount = *resp.Response.TotalCount
		}
		certs := resp.Response.Certificates
		if certs == nil {
			certs = []*tcssl.Certificates{}
		}
		for _, c := range certs {
			if c.Alias != nil && *c.Alias == storageKey {
				if c.CertEndTime != nil {
					t, err := time.Parse(time.RFC3339, *c.CertEndTime)
					if err != nil {
						t, err = time.Parse("2006-01-02 15:04:05", *c.CertEndTime)
					}
					if err == nil {
						platformNotAfter = &t
					}
				}
				break
			}
		}
		if platformNotAfter != nil {
			break
		}
		offset += uint64(len(certs))
		if totalCount > 0 && offset >= totalCount || len(certs) == 0 {
			break
		}
	}

	needUpload := false
	if platformNotAfter == nil {
		needUpload = true
	} else if cosNotAfter.After(*platformNotAfter) {
		needUpload = true
	}
	if !needUpload {
		fmt.Printf("腾讯证书平台已有 %s 的证书且不早于 COS，跳过上传。\n", storageKey)
		return nil
	}

	// Upload: certificate + decrypted private key (PEM strings)
	uploadReq := tcssl.NewUploadCertificateRequest()
	uploadReq.CertificatePublicKey = common.StringPtr(string(certPem))
	uploadReq.CertificatePrivateKey = common.StringPtr(string(keyPem))
	uploadReq.CertificateType = common.StringPtr("SVR")
	uploadReq.Alias = common.StringPtr(storageKey)
	uploadResp, err := client.UploadCertificate(uploadReq)
	if err != nil {
		return fmt.Errorf("upload certificate: %w", err)
	}
	if uploadResp.Response.CertificateId != nil {
		fmt.Printf("已将 COS 上的证书上传到腾讯证书平台，CertificateId: %s\n", *uploadResp.Response.CertificateId)
	} else {
		fmt.Println("已将 COS 上的证书上传到腾讯证书平台。")
	}
	return nil
}
