// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"log/slog"
	"math/rand"
	"net"
	"net/netip"
	"syscall"
	"time"
)

type Protocol int

const (
	TCP Protocol = iota
	UDP
)

var DEFAULT_ERROR_COUNT = 500
var MIN_RESTART_DELAY = 500
var MAX_RESTART_DELAY = 2000

func CheckOriginAllowed(remoteIP net.IP, opts options) bool {
	if len(opts.AllowedSubnets) == 0 {
		return true
	}

	for _, ipNet := range opts.AllowedSubnets {
		if ipNet.Contains(remoteIP) {
			return true
		}
	}
	return false
}

func DialUpstreamControl(sport int, opts options) func(string, string, syscall.RawConn) error {
	return func(network, address string, c syscall.RawConn) error {
		var syscallErr error
		err := c.Control(func(fd uintptr) {
			if opts.Protocol == "tcp" {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_SYNCNT, 2)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_TCP, TCP_SYNCTNT, 2): %w", syscallErr)
					return
				}
			}

			syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_TRANSPARENT, 1)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(IPPROTO_IP, IP_TRANSPARENT, 1): %w", syscallErr)
				return
			}

			syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
			if syscallErr != nil {
				syscallErr = fmt.Errorf("setsockopt(SOL_SOCKET, SO_REUSEADDR, 1): %w", syscallErr)
				return
			}

			if sport == 0 {
				ipBindAddressNoPort := 24
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, ipBindAddressNoPort, 1)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(SOL_SOCKET, IPPROTO_IP, %d): %w", opts.Mark, syscallErr)
					return
				}
			}

			if opts.Mark != 0 {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_MARK, opts.Mark)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(SOL_SOCK, SO_MARK, %d): %w", opts.Mark, syscallErr)
					return
				}
			}

			if network == "tcp6" || network == "udp6" {
				syscallErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 0)
				if syscallErr != nil {
					syscallErr = fmt.Errorf("setsockopt(IPPROTO_IP, IPV6_ONLY, 0): %w", syscallErr)
					return
				}
			}
		})

		if err != nil {
			return err
		}
		return syscallErr
	}
}

func ParseAndValidateOptions(config *map[string]*options, logger *slog.Logger) error {
	if config == nil {
		logger.Error("Invalid configuration provided: nil")
		return errors.New("Invalid configuration")
	}

	for name, opts := range *config {
		logger = logger.With(slog.String("Name", name))

		if opts == nil {
			logger.Error("options is nil")
			return errors.New("Invalid options in config: nil")
		}

		if opts.Name == "" {
			opts.Name = name
		}

		if opts.Protocol != "tcp" && opts.Protocol != "udp" {
			logger.Error("--protocol has to be one of udp, tcp", slog.String("protocol", opts.Protocol))
			return errors.New("Invalid protocol")
		}

		if opts.Mark < 0 {
			logger.Error("--mark has to be >= 0", slog.Int("mark", opts.Mark))
			return errors.New("Invalid mark")
		}

		if opts.Verbose < 0 {
			logger.Error("-v has to be >= 0", slog.Int("verbose", opts.Verbose))
			return errors.New("Invalid verbosity")
		}

		if opts.Listeners < 1 {
			logger.Error("--listeners has to be >= 1")
			return errors.New("Invalid listeners count")
		}

		var err error
		if opts.ListenAddr, err = netip.ParseAddrPort(opts.ListenAddrStr); err != nil {
			logger.Error("listen address is malformed", "error", err)
			return errors.New("Invalid listen address")
		}
		logger.Info("Parsed ipv4", slog.Any("ipv4", opts.ListenAddr))

		if opts.TargetAddr4, err = netip.ParseAddrPort(opts.TargetAddr4Str); err != nil {
			logger.Error("ipv4 target address is malformed", "error", err)
			return errors.New("Invalid ipv4 address")
		}
		if !opts.TargetAddr4.Addr().Is4() {
			logger.Error("ipv4 target address is not IPv4")
			return errors.New("Invalid ipv4 address")
		}

		if opts.TargetAddr6, err = netip.ParseAddrPort(opts.TargetAddr6Str); err != nil {
			logger.Error("ipv6 target address is malformed", "error", err)
			return errors.New("Invalid ipv6 address")
		}
		if !opts.TargetAddr6.Addr().Is6() {
			logger.Error("ipv6 target address is not IPv6")
			return errors.New("Invalid ipv6 address")
		}

		if opts.udpCloseAfter < 0 {
			logger.Error("--close-after has to be >= 0", slog.Int("close-after", opts.udpCloseAfter))
			return errors.New("Invalid close after")
		}
		opts.UDPCloseAfter = time.Duration(opts.udpCloseAfter) * time.Second

		if opts.MaxErrorCount < 0 {
			logger.Error("--max-error-count has to be >= 0", slog.Int("max-error-count", opts.MaxErrorCount))
			return errors.New("Invalid max error count")
		}

		if opts.MaxErrorCount == 0 {
			opts.MaxErrorCount = DEFAULT_ERROR_COUNT
		}
	}

	return nil
}

func getRandomDelay() int {
	return rand.Intn(MAX_RESTART_DELAY-MIN_RESTART_DELAY) + MIN_RESTART_DELAY
}
