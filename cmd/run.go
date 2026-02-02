package cmd

import (
	"context"
	"fmt"
	"os"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/registration"
	"github.com/go-acme/lego/v4/providers/dns/cloudflare"
	"github.com/leonco/certcos/account"
	"github.com/leonco/certcos/cert"
	"github.com/leonco/certcos/cos"
)

// Config holds all input (env + CLI).
type Config struct {
	Domains []string // comma-separated domains, all covered by one certificate
	Email   string
	COS     cos.Config
	EncKey  []byte
	CADir   string // optional, default Let's Encrypt production
}

// Run loads env into Config, ensures account and certificate, then exits.
func Run(cfg Config) error {
	ctx := context.Background()

	store, err := cos.NewStore(cfg.COS)
	if err != nil {
		return fmt.Errorf("cos: %w", err)
	}

	// Load or create ACME user
	u, err := account.LoadOrCreateUser(ctx, store, cfg.Email, cfg.EncKey)
	if err != nil {
		return fmt.Errorf("account: %w", err)
	}

	legoCfg := lego.NewConfig(u)
	legoCfg.Certificate.KeyType = certcrypto.RSA2048
	if cfg.CADir != "" {
		legoCfg.CADirURL = cfg.CADir
	}

	client, err := lego.NewClient(legoCfg)
	if err != nil {
		return fmt.Errorf("lego client: %w", err)
	}

	// DNS-01 with Cloudflare (reads CF_DNS_API_TOKEN or CLOUDFLARE_DNS_API_TOKEN from env)
	provider, err := cloudflare.NewDNSProvider()
	if err != nil {
		return fmt.Errorf("cloudflare dns: %w", err)
	}
	if err := client.Challenge.SetDNS01Provider(provider); err != nil {
		return fmt.Errorf("set dns01: %w", err)
	}

	// New account: register and save to COS
	if u.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return fmt.Errorf("register: %w", err)
		}
		u.Registration = reg
		if err := account.SaveUser(ctx, store, u, cfg.EncKey); err != nil {
			return fmt.Errorf("save account: %w", err)
		}
	}

	mgr := cert.NewManager(store, cfg.EncKey, client)
	updated, err := mgr.EnsureCertificate(ctx, cfg.Domains)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	if updated {
		fmt.Fprintf(os.Stderr, "Certificate for %v obtained or renewed and saved to COS.\n", cfg.Domains)
	} else {
		fmt.Fprintf(os.Stderr, "Certificate for %v already valid; no change.\n", cfg.Domains)
	}
	return nil
}
