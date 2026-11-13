package portscan

import (
	"context"
	"fmt"
	"net"
	"time"
)

// config внутренние параметры сканера.
type config struct {
	concurrency    int
	connectTimeout time.Duration
	resolver       Resolver
}

func defaultConfig() config {
	return config{
		concurrency:    100,
		connectTimeout: 2 * time.Second,
		resolver:       nil,
	}
}

type Option func(*config) error

func WithConcurrency(n int) Option {
	return func(c *config) error {
		if n < 1 {
			return fmt.Errorf("portscan: concurrency must be >= 1, got %d", n)
		}
		c.concurrency = n
		return nil
	}
}

func WithConnectTimeout(d time.Duration) Option {
	return func(c *config) error {
		if d <= 0 {
			return fmt.Errorf("portscan: connect timeout must be > 0, got %s", d)
		}
		c.connectTimeout = d
		return nil
	}
}

// WithResolver позволяет внедрить кастомный DNS-резолвер.
func WithResolver(r Resolver) Option {
	return func(c *config) error {
		c.resolver = r
		return nil
	}
}

// Resolver — интерфейс, абстрагирующий системный DNS-резолвер стандартной библиотеки.
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// defaultResolver реализует интерфейс Resolver поверх net.DefaultResolver.
type defaultResolver struct{}

func (defaultResolver) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return net.DefaultResolver.LookupIPAddr(ctx, host)
}
