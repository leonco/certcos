package cmd

import (
	"context"
	"crypto/x509"
	"encoding/json"
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
func RunSyncCert(domain string, store *cos.Store, encKey []byte, secretID, secretKey string, resourceTypesRegions map[string][]string) error {
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
	fmt.Printf("[sync-cert] COS 证书过期时间: %s (UTC)\n", cosNotAfter.UTC().Format("2006-01-02 15:04:05"))

	// Tencent SSL client (SSL API does not require region; use empty or ap-guangzhou)
	cred := common.NewCredential(secretID, secretKey)
	client, err := tcssl.NewClient(cred, "", profile.NewClientProfile())
	if err != nil {
		return fmt.Errorf("tencent ssl client: %w", err)
	}

	// List certificates and find those matching this domain (by Alias = storageKey)
	req := tcssl.NewDescribeCertificatesRequest()
	req.SearchKey = common.StringPtr(storageKey)
	type matchedCert struct {
		id       string
		notAfter time.Time
	}
	var matchedCerts []matchedCert
	var totalCount uint64
	cst := time.FixedZone("CST", 8*3600)
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
			if c.Alias == nil || *c.Alias != storageKey {
				continue
			}
			if c.CertificateId == nil {
				continue
			}
			mc := matchedCert{id: *c.CertificateId}
			if c.CertEndTime != nil {
				t, err := time.ParseInLocation(time.RFC3339, *c.CertEndTime, cst)
				if err != nil {
					t, err = time.ParseInLocation("2006-01-02 15:04:05", *c.CertEndTime, cst)
				}
				if err == nil {
					mc.notAfter = t
				}
			}
			matchedCerts = append(matchedCerts, mc)
		}
		offset += uint64(len(certs))
		if totalCount > 0 && offset >= totalCount || len(certs) == 0 {
			break
		}
	}

	// Pick the newest cert (latest NotAfter) as reference; rest are stale duplicates
	var platformNotAfter *time.Time
	var platformCertId string
	var staleCertIds []string
	if len(matchedCerts) > 0 {
		newest := 0
		for i := 1; i < len(matchedCerts); i++ {
			if matchedCerts[i].notAfter.After(matchedCerts[newest].notAfter) {
				newest = i
			}
		}
		platformCertId = matchedCerts[newest].id
		platformNotAfter = &matchedCerts[newest].notAfter
		fmt.Printf("[sync-cert] 平台找到 %d 个同名证书，最新 CertId: %s, 过期: %s (CST)\n",
			len(matchedCerts), platformCertId, platformNotAfter.In(cst).Format("2006-01-02 15:04:05"))
		for i, mc := range matchedCerts {
			if i != newest {
				staleCertIds = append(staleCertIds, mc.id)
				fmt.Printf("[sync-cert] 待清理旧证书: %s\n", mc.id)
			}
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

	if platformCertId != "" {
		// Platform has existing cert → upload new, update COS, clean up old
		// Step 1: Upload new certificate
		uploadReq := tcssl.NewUploadCertificateRequest()
		uploadReq.CertificatePublicKey = common.StringPtr(string(certPem))
		uploadReq.CertificatePrivateKey = common.StringPtr(string(keyPem))
		uploadReq.CertificateType = common.StringPtr("SVR")
		uploadReq.Alias = common.StringPtr(storageKey)
		uploadResp, err := client.UploadCertificate(uploadReq)
		if err != nil {
			return fmt.Errorf("upload new certificate: %w", err)
		}
		newCertId := *uploadResp.Response.CertificateId
		fmt.Printf("[sync-cert] Step 1: 新证书上传成功, CertificateId: %s\n", newCertId)

		// Step 2: Update COS resource to use new certificate
		updateReq := tcssl.NewUpdateCertificateInstanceRequest()
		updateReq.OldCertificateId = common.StringPtr(platformCertId)
		updateReq.CertificateId = common.StringPtr(newCertId)
		if len(resourceTypesRegions) > 0 {
			var types []string
			var rr []*tcssl.ResourceTypeRegions
			for rt, regions := range resourceTypesRegions {
				types = append(types, rt)
				rr = append(rr, &tcssl.ResourceTypeRegions{
					ResourceType: common.StringPtr(rt),
					Regions:      common.StringPtrs(regions),
				})
			}
			updateReq.ResourceTypes = common.StringPtrs(types)
			updateReq.ResourceTypesRegions = rr
		}
		reqJSON := updateReq.ToJsonString()
		fmt.Printf("[sync-cert] Step 2 更新请求: %s\n", reqJSON)
		updateResp, err := client.UpdateCertificateInstance(updateReq)
		if err != nil {
			// Step 2 failed, new cert is orphaned but not deployed — delete it
			errJSON, _ := json.Marshal(err)
			fmt.Printf("[sync-cert] Step 2 更新失败: %s\n", string(errJSON))
			delReq := tcssl.NewDeleteCertificateRequest()
			delReq.CertificateId = common.StringPtr(newCertId)
			if _, delErr := client.DeleteCertificate(delReq); delErr != nil {
				fmt.Printf("[sync-cert] 清理孤儿证书 %s 失败: %v\n", newCertId, delErr)
			} else {
				fmt.Printf("[sync-cert] 已清理孤儿证书 %s\n", newCertId)
			}
			return fmt.Errorf("update certificate: %w", err)
		}
		respJSON := updateResp.ToJsonString()
		fmt.Printf("[sync-cert] Step 2 更新成功: %s\n", respJSON)

		// Step 3: Delete all old certificates (warn only on failure)
		oldIds := append([]string{platformCertId}, staleCertIds...)
		for _, id := range oldIds {
			delReq := tcssl.NewDeleteCertificateRequest()
			delReq.CertificateId = common.StringPtr(id)
			delResp, err := client.DeleteCertificate(delReq)
			if err != nil {
				fmt.Printf("[sync-cert] Step 3 删除旧证书 %s 失败: %v\n", id, err)
			} else {
				delJSON, _ := json.Marshal(delResp)
				fmt.Printf("[sync-cert] Step 3 已删除旧证书 %s: %s\n", id, string(delJSON))
			}
		}

		// Step 1 already set alias, Step 2 uses CertificateId (not pub/priv key) so alias stays intact
	} else {
		// No existing cert on platform → upload new
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
	}
	return nil
}
