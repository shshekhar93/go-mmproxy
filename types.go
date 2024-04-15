package main

import (
	"log/slog"
	"net"
	"net/netip"
	"time"
)

type options struct {
	Name               string `yaml:"name"`
	Protocol           string `yaml:"protocol"`
	ListenAddrStr      string `yaml:"listen-addr"`
	TargetAddr4Str     string `yaml:"target-addr-v4"`
	TargetAddr6Str     string `yaml:"target-addr-v6"`
	ListenAddr         netip.AddrPort
	TargetAddr4        netip.AddrPort
	TargetAddr6        netip.AddrPort
	Mark               int    `yaml:"mark"`
	Verbose            int    `yaml:"verbosity"`
	allowedSubnetsPath string `yaml:"allowed-subnets-path"`
	AllowedSubnets     []*net.IPNet
	Listeners          int `yaml:"listeners"`
	Logger             *slog.Logger
	udpCloseAfter      int `yaml:"udp-close-after"`
	UDPCloseAfter      time.Duration
	ConfigPath         string
}

func (opts *options) defaultsFrom(defaultOptions *options) {
	if opts.allowedSubnetsPath == "" {
		opts.allowedSubnetsPath = defaultOptions.allowedSubnetsPath
		opts.AllowedSubnets = defaultOptions.AllowedSubnets
	}

	if opts.Protocol == "" {
		opts.Protocol = defaultOptions.Protocol
	}

	if opts.Mark == 0 {
		opts.Mark = defaultOptions.Mark
	}

	if opts.Verbose == 0 {
		opts.Verbose = defaultOptions.Verbose
	}

	if opts.Listeners == 0 {
		opts.Listeners = defaultOptions.Listeners
	}

	if opts.udpCloseAfter == 0 {
		opts.udpCloseAfter = defaultOptions.udpCloseAfter
	}
}
