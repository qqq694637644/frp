// Copyright 2023 The frp Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package validation

import (
	"errors"
	"fmt"
	"slices"

	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/pkg/transport/socks5udp"
	"github.com/fatedier/frp/pkg/transport/xtcpdatagram"
)

func ValidateVisitorConfigurer(c v1.VisitorConfigurer) error {
	base := c.GetBaseConfig()
	if err := validateVisitorBaseConfig(base); err != nil {
		return err
	}

	switch v := c.(type) {
	case *v1.STCPVisitorConfig:
	case *v1.SUDPVisitorConfig:
	case *v1.XTCPVisitorConfig:
		return validateXTCPVisitorConfig(v)
	default:
		return errors.New("unknown visitor config type")
	}
	return nil
}

func validateVisitorBaseConfig(c *v1.VisitorBaseConfig) error {
	if c.Name == "" {
		return errors.New("name is required")
	}

	if c.ServerName == "" {
		return errors.New("server name is required")
	}

	if c.BindPort == 0 {
		return errors.New("bind port is required")
	}
	return nil
}

func validateXTCPVisitorConfig(c *v1.XTCPVisitorConfig) error {
	if !slices.Contains([]string{"kcp", "quic"}, c.Protocol) {
		return fmt.Errorf("protocol should be kcp or quic")
	}
	if c.Datagram != nil && c.Protocol != "quic" {
		return fmt.Errorf("XTCP datagram requires protocol = quic")
	}
	if err := xtcpdatagram.Validate(c.Datagram); err != nil {
		return err
	}
	if c.Datagram != nil && (c.NatTraversal == nil || c.NatTraversal.UDPProxyURL == "") {
		return fmt.Errorf("XTCP DATAGRAM Visitor requires natTraversal.udpProxyURL (no direct UDP fallback)")
	}
	if c.NatTraversal != nil && c.NatTraversal.UDPProxyURL != "" {
		if c.Protocol != "quic" {
			return fmt.Errorf("SOCKS5 UDP XTCP traversal requires QUIC")
		}
		if err := socks5udp.ValidateURL(c.NatTraversal.UDPProxyURL); err != nil {
			return err
		}
		if !c.NatTraversal.DisableAssistedAddrs {
			return fmt.Errorf("SOCKS5 UDP traversal requires disableAssistedAddrs=true")
		}
		if c.FallbackTo != "" {
			return fmt.Errorf("SOCKS5 UDP traversal disallows fallbackTo")
		}
	}
	return nil
}
