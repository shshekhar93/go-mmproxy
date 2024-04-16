// Copyright 2019 Path Network, Inc. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package main

import (
	"bufio"
	"errors"
	"flag"
	"log/slog"
	"net"
	"os"
	"syscall"

	yaml "gopkg.in/yaml.v3"
)

var CommandlineOpts options

func init() {
	flag.StringVar(&CommandlineOpts.Protocol, "p", "tcp", "Protocol that will be proxied: tcp, udp")
	flag.StringVar(&CommandlineOpts.ListenAddrStr, "l", "0.0.0.0:8443", "Address the proxy listens on")
	flag.StringVar(&CommandlineOpts.TargetAddr4Str, "4", "127.0.0.1:443", "Address to which IPv4 traffic will be forwarded to")
	flag.StringVar(&CommandlineOpts.TargetAddr6Str, "6", "[::1]:443", "Address to which IPv6 traffic will be forwarded to")
	flag.IntVar(&CommandlineOpts.Mark, "mark", 0, "The mark that will be set on outbound packets")
	flag.IntVar(&CommandlineOpts.Verbose, "v", 0, `0 - no logging of individual connections
1 - log errors occurring in individual connections
2 - log all state changes of individual connections`)
	flag.StringVar(&CommandlineOpts.allowedSubnetsPath, "allowed-subnets", "",
		"Path to a file that contains allowed subnets of the proxy servers")
	flag.IntVar(&CommandlineOpts.Listeners, "listeners", 1,
		"Number of listener sockets that will be opened for the listen address (Linux 3.9+)")
	flag.IntVar(&CommandlineOpts.udpCloseAfter, "close-after", 60, "Number of seconds after which UDP socket will be cleaned up")
	flag.StringVar(&CommandlineOpts.ConfigPath, "config", "", "Config file path")
	flag.IntVar(&CommandlineOpts.MaxErrorCount, "max-error-count", 1, "Number of listen errors after which the process will be terminated")
}

func listen(listenerNum int, opts options, errors chan<- error) {
	logger := opts.Logger.With(slog.String("name", opts.Name), slog.Int("listenerNum", listenerNum),
		slog.String("protocol", opts.Protocol), slog.String("listenAdr", opts.ListenAddr.String()))

	listenConfig := net.ListenConfig{}
	if opts.Listeners > 1 {
		listenConfig.Control = func(network, address string, c syscall.RawConn) error {
			return c.Control(func(fd uintptr) {
				soReusePort := 15
				if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, soReusePort, 1); err != nil {
					logger.Warn("failed to set SO_REUSEPORT - only one listener setup will succeed")
				}
			})
		}
	}

	if opts.Protocol == "tcp" {
		TCPListen(&listenConfig, opts, logger, errors)
	} else {
		UDPListen(&listenConfig, opts, logger, errors)
	}
}

func loadAllowedSubnets(opts *options, logger *slog.Logger) error {
	file, err := os.Open(opts.allowedSubnetsPath)
	if err != nil {
		return err
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		_, ipNet, err := net.ParseCIDR(scanner.Text())
		if err != nil {
			return err
		}
		opts.AllowedSubnets = append(opts.AllowedSubnets, ipNet)
		logger.Info("allowed subnet", slog.String("subnet", ipNet.String()))
	}

	return nil
}

func loadConfig(path string, config *map[string]*options, logger *slog.Logger) error {
	if config == nil {
		return errors.New("Invalid config map")
	}

	buf, err := os.ReadFile(CommandlineOpts.ConfigPath)
	if err != nil {
		return err
	}

	err = yaml.Unmarshal(buf, config)
	if err != nil {
		return err
	}

	// Normalize and set defaults
	for _, opts := range *config {
		opts.Logger = logger
		if opts.allowedSubnetsPath != "" {
			loadAllowedSubnets(opts, logger)
		}
		opts.defaultsFrom(&CommandlineOpts)
	}

	return nil
}

func main() {
	flag.Parse()
	lvl := slog.LevelInfo
	if CommandlineOpts.Verbose > 0 {
		lvl = slog.LevelDebug
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
	CommandlineOpts.Logger = logger

	if CommandlineOpts.allowedSubnetsPath != "" {
		if err := loadAllowedSubnets(&CommandlineOpts, logger); err != nil {
			logger.Error("failed to load allowed subnets file", "path", CommandlineOpts.allowedSubnetsPath, "error", err)
		}
	}

	config := map[string]*options{}
	if CommandlineOpts.ConfigPath != "" {
		var err error
		err = loadConfig(CommandlineOpts.ConfigPath, &config, logger)

		if err != nil {
			logger.Error("Failed to load config file", "path", CommandlineOpts.ConfigPath, "error", err)
		}
		logger.Debug("Config parsed from config file", slog.Any("config", config))
	}

	if len(config) == 0 {
		config["Default"] = &CommandlineOpts
	}

	err := ParseAndValidateOptions(&config, logger)
	if err != nil {
		os.Exit(1)
	}

	totalListenersCount := 0
	for _, opts := range config {
		totalListenersCount += opts.Listeners
	}

	listenErrors := make(chan error, totalListenersCount)
	for _, opts := range config {
		for i := 0; i < opts.Listeners; i++ {
			go listen(i, *opts, listenErrors)
		}
	}

	for i := 0; i < CommandlineOpts.MaxErrorCount; i++ {
		<-listenErrors
	}
	logger.Warn("Too many errors, exiting the process")
	os.Exit(1)
}
