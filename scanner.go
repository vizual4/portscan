package portscan

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// Scanner выполняет параллельное TCP connect-сканирование.
type Scanner struct {
	cfg config
}

// New создает новый экземпляр Scanner с применением переданных опций.
func New(opts ...Option) (*Scanner, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if err := opt(&cfg); err != nil {
			return nil, err
		}
	}
	return &Scanner{cfg: cfg}, nil
}

// Scan запускает сканирование хостов и портов. Возвращает канал результатов (<-chan Result).
func (s *Scanner) Scan(ctx context.Context, hosts []string, spec PortSpec) (<-chan Result, error) {
	if ctx == nil {
		return nil, fmt.Errorf("portscan: context must not be nil")
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("portscan: at least one host is required")
	}
	if spec.Len() == 0 {
		return nil, fmt.Errorf("portscan: at least one port is required")
	}

	targets, err := s.resolveAll(ctx, hosts)
	if err != nil {
		return nil, err
	}

	bufSize := s.cfg.concurrency
	results := make(chan Result, bufSize)

	go s.scan(ctx, targets, spec, results)

	return results, nil
}

type target struct {
	host string
	ip   net.IP
}

// resolveAll выполняет DNS-запросы и дедуплицирует полученные IP-адреса.
func (s *Scanner) resolveAll(ctx context.Context, hosts []string) ([]target, error) {
	var targets []target
	seen := make(map[string]struct{})

	for _, host := range hosts {
		if host == "" {
			continue
		}

		if ip := net.ParseIP(host); ip != nil {
			key := host + ":" + ip.String()
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				targets = append(targets, target{host: host, ip: ip})
			}
			continue
		}

		resolver := s.cfg.resolver
		if resolver == nil {
			resolver = defaultResolver{}
		}

		addrs, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, fmt.Errorf("portscan: failed to resolve %q: %w", host, err)
		}

		for _, addr := range addrs {
			key := host + ":" + addr.IP.String()
			if _, ok := seen[key]; !ok {
				seen[key] = struct{}{}
				targets = append(targets, target{host: host, ip: addr.IP})
			}
		}
	}

	if len(targets) == 0 {
		return nil, fmt.Errorf("portscan: no valid targets after resolution")
	}

	return targets, nil
}

// scan управляет конкурентным выполнением через семафор.
func (s *Scanner) scan(ctx context.Context, targets []target, spec PortSpec, results chan<- Result) {
	defer close(results)

	sem := make(chan struct{}, s.cfg.concurrency)
	var wg sync.WaitGroup

	for _, t := range targets {
		for _, port := range spec.Ports() {
			select {
			case <-ctx.Done():
				wg.Wait()
				return
			default:
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(t target, port uint16) {
				defer wg.Done()
				defer func() { <-sem }()

				result := s.scanPort(ctx, t, port)

				select {
				case results <- result:
				case <-ctx.Done():
					timer := time.NewTimer(100 * time.Millisecond)
					defer timer.Stop()
					select {
					case results <- result:
					case <-timer.C:
					}
				}
			}(t, port)
		}
	}

	wg.Wait()
}

// scanPort выполняет единичное TCP-подключение к конкретному IP и порту.
func (s *Scanner) scanPort(ctx context.Context, t target, port uint16) Result {
	start := time.Now()

	connCtx, cancel := context.WithTimeout(ctx, s.cfg.connectTimeout)
	defer cancel()

	addr := formatAddr(t.ip, port)

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(connCtx, "tcp", addr)
	duration := time.Since(start)

	if conn != nil {
		conn.Close()
	}

	state := classify(err)

	result := Result{
		Host:     t.host,
		IP:       t.ip,
		Port:     port,
		State:    state,
		Duration: duration,
	}

	if state == StateError {
		result.Err = err
	}

	return result
}

func formatAddr(ip net.IP, port uint16) string {
	if ip.To4() != nil {
		return fmt.Sprintf("%s:%d", ip.String(), port)
	}
	return fmt.Sprintf("[%s]:%d", ip.String(), port)
}
