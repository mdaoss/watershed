// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

package config

import (
	"log"
	"os"
	"time"

	"watershed/internal/bgp"
	"gopkg.in/yaml.v3"
)

const defaultConfigPath = "ws.config.yaml"

// Config - explicit better than implicit - so no any defaults
type Config struct {
	LogLevel               int           `yaml:"logLevel"`
	TerminationGracePeriod time.Duration `yaml:"terminationGracePeriod"`
	TcpProbeInterval       time.Duration `yaml:"tcpProbeInterval"`
	PeerPort               uint16        `yaml:"peerPort"`
	MetricsPort            uint16        `yaml:"metricsPort"`
	BGPConfig              bgp.BGPConfig `yaml:"bgp"`
}

func InitRunningConfig() *Config {
	var runningConfig Config
	yamlConfigFileBytes, err := os.ReadFile(defaultConfigPath)
	if err != nil {
		log.Fatalln("failed to read config from file: " + err.Error())
	}

	err = yaml.Unmarshal(yamlConfigFileBytes, &runningConfig)
	if err != nil {
		log.Fatalf("error unmarshaling YAML from config file: %v", err)
	}

	return &runningConfig
}
