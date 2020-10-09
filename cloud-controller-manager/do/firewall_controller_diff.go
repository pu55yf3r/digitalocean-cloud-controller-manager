/*
Copyright 2020 DigitalOcean

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package do

import (
	"strings"

	"github.com/digitalocean/godo"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

type comparableFirewall struct {
	Name          string
	InboundRules  []godo.InboundRule
	OutboundRules []godo.OutboundRule
	Tags          []string
}

func firewallRequestEqual(fw *godo.Firewall, fr *godo.FirewallRequest) (bool, string) {
	cf1 := compFirewallFromFirewall(fw)
	cf2 := compFirewallFromFirewallRequest(fr)

	return compFirewallsEqual(cf1, cf2)
}

func firewallsEqual(fw1, fw2 *godo.Firewall) (bool, string) {
	cf1 := compFirewallFromFirewall(fw1)
	cf2 := compFirewallFromFirewall(fw2)

	return compFirewallsEqual(cf1, cf2)
}

func compFirewallsEqual(cf1, cf2 *comparableFirewall) (bool, string) {
	if cf1 == nil && cf2 == nil {
		return true, ""
	}

	if cf1 == nil || cf2 == nil {
		return false, ""
	}

	sorter := cmpopts.SortSlices(func(r1, r2 godo.OutboundRule) bool {
		return printOutboundRule(r1) < printOutboundRule(r2)
	})

	portRangeFilter := cmp.FilterPath(func(p cmp.Path) bool {
		switch p.String() {
		case "InboundRules.PortRange", "OutboundRules.PortRange":
			return true
		}
		return false
	}, cmp.Comparer(func(pr1, pr2 string) bool {
		sanitizePortRange := func(pr string) string {
			if pr == "" || pr == "0" || pr == "all" {
				pr = "0"
			}
			return pr
		}

		return sanitizePortRange(pr1) == sanitizePortRange(pr2)
	}))

	ruleDetailsFilter := cmp.FilterPath(func(p cmp.Path) bool {
		if strings.HasPrefix(p.String(), "InboundRules.Sources") || strings.HasPrefix(p.String(), "OutboundRules.Destinations") {
			return p.Last().String() != ".Addresses"
		}

		return false
	}, cmp.Ignore())

	diff := cmp.Diff(cf1, cf2, sorter, portRangeFilter, ruleDetailsFilter)
	return diff == "", diff
}

func compFirewallFromFirewall(fw *godo.Firewall) *comparableFirewall {
	if fw == nil {
		return nil
	}

	return &comparableFirewall{
		Name:          fw.Name,
		InboundRules:  fw.InboundRules,
		OutboundRules: fw.OutboundRules,
		Tags:          fw.Tags,
	}
}

func compFirewallFromFirewallRequest(fr *godo.FirewallRequest) *comparableFirewall {
	if fr == nil {
		return nil
	}

	return &comparableFirewall{
		Name:          fr.Name,
		InboundRules:  fr.InboundRules,
		OutboundRules: fr.OutboundRules,
		Tags:          fr.Tags,
	}
}
