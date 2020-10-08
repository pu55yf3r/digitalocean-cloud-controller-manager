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
	"context"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/digitalocean/godo"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/prometheus/client_golang/prometheus"
	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/wait"
	coreinformers "k8s.io/client-go/informers/core/v1"
	clientset "k8s.io/client-go/kubernetes"
	corelisters "k8s.io/client-go/listers/core/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"
	"k8s.io/klog/v2"
)

const (
	// Frequency at which the firewall controller runs.
	firewallReconcileFrequency = 5 * time.Second
	// Timeout value for processing worker items taken from the queue.
	processWorkerItemTimeout = 30 * time.Second
	originEvent              = "event"
	originFirewallLoop       = "firewall_loop"
	queueKey                 = "service"

	// How long to wait before retrying the processing of a firewall change.
	minRetryDelay = 1 * time.Second
	maxRetryDelay = 5 * time.Minute
)

var (
	allowAllOutboundRules = []godo.OutboundRule{
		{
			Protocol:  "tcp",
			PortRange: "all",
			Destinations: &godo.Destinations{
				Addresses: []string{"0.0.0.0/0", "::/0"},
			},
		},
		{
			Protocol:  "udp",
			PortRange: "all",
			Destinations: &godo.Destinations{
				Addresses: []string{"0.0.0.0/0", "::/0"},
			},
		},
		{
			Protocol: "icmp",
			Destinations: &godo.Destinations{
				Addresses: []string{"0.0.0.0/0", "::/0"},
			},
		},
	}
)

// firewallCache stores a cached firewall and mutex to handle concurrent access.
type firewallCache struct {
	mu       *sync.RWMutex // protects firewall.
	firewall *godo.Firewall
}

// firewallManager manages the interaction with the DO Firewalls API.
type firewallManager struct {
	client             *godo.Client
	fwCache            firewallCache
	workerFirewallName string
	workerFirewallTags []string
	metrics            metrics
}

// FirewallController helps to keep cloud provider service firewalls in sync.
type FirewallController struct {
	kubeClient         clientset.Interface
	client             *godo.Client
	workerFirewallTags []string
	workerFirewallName string
	serviceLister      corelisters.ServiceLister
	fwManager          firewallManager
	metrics            metrics
	queue              workqueue.RateLimitingInterface
}

// NewFirewallController returns a new firewall controller to reconcile public access firewall state.
func NewFirewallController(
	ctx context.Context,
	kubeClient clientset.Interface,
	client *godo.Client,
	serviceInformer coreinformers.ServiceInformer,
	fwManager firewallManager,
	workerFirewallTags []string,
	workerFirewallName string,
	metrics metrics,
) *FirewallController {
	fc := &FirewallController{
		kubeClient:         kubeClient,
		client:             client,
		workerFirewallTags: workerFirewallTags,
		workerFirewallName: workerFirewallName,
		fwManager:          fwManager,
		metrics:            metrics,
		queue:              workqueue.NewNamedRateLimitingQueue(workqueue.NewItemExponentialFailureRateLimiter(minRetryDelay, maxRetryDelay), "firewall"),
	}

	serviceInformer.Informer().AddEventHandlerWithResyncPeriod(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(cur interface{}) {
				fc.queue.Add(queueKey)
			},
			UpdateFunc: func(old, cur interface{}) {
				fc.queue.Add(queueKey)
			},
			DeleteFunc: func(cur interface{}) {
				fc.queue.Add(queueKey)
			},
		},
		0,
	)
	fc.serviceLister = serviceInformer.Lister()

	return fc
}

// Run starts the firewall controller loop.
func (fc *FirewallController) Run(ctx context.Context, stopCh <-chan struct{}, fwReconcileFrequency time.Duration) {
	// Use PollUntil instead of Until to wait one fwReconcileFrequency interval
	// before syncing the cloud firewall: when the firewall controller starts
	// up, the event handler is triggered as the cache gets populated and runs
	// through all services already. There is no need to for us to do so again
	// from here.
	wait.PollUntil(fwReconcileFrequency, func() (done bool, err error) {
		klog.V(5).Info("running cloud firewall sync loop")
		runErr := fc.observeRunLoopDuration(ctx)
		if runErr != nil && ctx.Err() == nil {
			klog.Errorf("failed to run firewall reconcile loop: %v", runErr)
		}
		return false, nil
	}, stopCh)
	fc.queue.ShutDown()
}

func (fc *FirewallController) runWorker() {
	for fc.processNextItem() {
	}
}

func (fc *FirewallController) processNextItem() bool {
	// Wait until there is a new item in the working queue
	key, quit := fc.queue.Get()
	if quit {
		return false
	}
	// Tell the queue that we are done with processing this key. This unblocks the key for other workers
	// This allows safe parallel processing because items with the same key are never processed in
	// parallel.
	defer fc.queue.Done(key)

	ctx, cancel := context.WithTimeout(context.Background(), processWorkerItemTimeout)
	defer cancel()
	err := fc.observeReconcileDuration(ctx, originEvent)
	if err != nil {
		klog.Errorf("failed to process worker item: %v", err)
		fc.queue.AddRateLimited(key)
	}
	fc.queue.Forget(key)
	return true
}

func (fc *FirewallController) reconcileCloudFirewallChanges(ctx context.Context) error {
	currentFirewall, err := fc.fwManager.Get(ctx)
	if err != nil {
		return fmt.Errorf("failed to get worker firewall: %s", err)
	}
	if currentFirewall != nil {
		if fc.fwManager.fwCache.isEqual(currentFirewall) {
			return nil
		}
	}
	fc.fwManager.fwCache.updateCache(currentFirewall)
	klog.Info("issuing firewall reconcile")
	fc.queue.Add(queueKey)

	return nil
}

// Get returns the current public access firewall representation.
func (fm *firewallManager) Get(ctx context.Context) (*godo.Firewall, error) {
	// check cache and query the API firewall service to get firewall by ID, if it exists. Return it. If not, continue.
	fw := fm.fwCache.getCachedFirewall()
	if fw != nil {
		var (
			resp *godo.Response
			err  error
		)
		fw, resp, err := func() (*godo.Firewall, *godo.Response, error) {
			var (
				code   int
				method string
			)
			// The ObserverFunc gets called by the deferred ObserveDuration. The
			// method and code values will be set before ObserveDuration is called
			// with the value returned from the response from the Firewall API request.
			timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
				fm.metrics.apiRequestDuration.With(prometheus.Labels{"method": method, "code": strconv.FormatInt(int64(code), 10)}).Observe(v)
			}))
			defer timer.ObserveDuration()
			fw, resp, err := fm.client.Firewalls.Get(ctx, fw.ID)
			if resp != nil {
				code = resp.StatusCode
				if resp.Request != nil {
					method = resp.Request.Method
				}
			}
			return fw, resp, err
		}()

		if err != nil && (resp == nil || resp.StatusCode != http.StatusNotFound) {
			return nil, fmt.Errorf("could not get firewall: %v", err)
		}
		if resp.StatusCode == http.StatusNotFound {
			klog.Warning("unable to retrieve firewall by ID because it no longer exists")
		}
		if fw != nil {
			return fw, nil
		}
	}

	// iterate through firewall API provided list and return the firewall with the matching firewall name.
	f := func(fw godo.Firewall) bool {
		return fw.Name == fm.workerFirewallName
	}
	klog.Infof("filtering firewall list for firewall name %q", fm.workerFirewallName)
	fw, err := func() (*godo.Firewall, error) {
		var (
			code   int
			method string
		)
		// The ObserverFunc gets called by the deferred ObserveDuration. The
		// method and code values will be set before ObserveDuration is called
		// with the value returned from the response from the Firewall API request.
		timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
			fm.metrics.apiRequestDuration.With(prometheus.Labels{"method": method, "code": strconv.FormatInt(int64(code), 10)}).Observe(v)
		}))
		defer timer.ObserveDuration()
		fw, resp, err := filterFirewallList(ctx, fm.client, f)
		if resp != nil {
			code = resp.StatusCode
			if resp.Request != nil {
				method = resp.Request.Method
			}
		}
		return fw, err
	}()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve list of firewalls from DO API: %v", err)
	}
	if fw != nil {
		klog.Infof("found firewall %q by listing", fm.workerFirewallName)
	} else {
		klog.Infof("could not find firewall %q by listing", fm.workerFirewallName)
	}
	return fw, nil
}

// Set applies the given firewall request configuration to the public access firewall if there is a delta.
// Specifically Set will reconcile away any changes to the inbound rules, outbound rules, firewall name and/or tags.
func (fm *firewallManager) Set(ctx context.Context, fr *godo.FirewallRequest) error {
	targetFirewall := fm.fwCache.getCachedFirewall()

	if targetFirewall != nil {
		diff := firewallDiff(targetFirewall, fr)
		if diff == "" {
			// A locally cached firewall with matching rules, correct name and tags means there is nothing to update.
			klog.Info("skipping firewall update since it matches the cache")
			return nil
		}
		klog.Infof("firewall configuration mismatch on parts (diffs: %s)", diff)
		// klog.Infof("firewall configuration mismatch on parts (diff:\ncurrent: %s\ntarget:  %s)", printRelevantFirewallRequestParts(fr), printRelevantFirewallParts(targetFirewall))

		// A locally cached firewall exists, but is does not match the expected
		// service inbound rules, outbound rules, name or tags. So we need to use the locally
		// cached firewall ID to attempt to update the firewall APIs representation of the
		// firewall with the new rules
		currentFirewall, resp, err := fm.updateFirewall(ctx, targetFirewall.ID, fr)
		if err == nil {
			klog.Info("successfully updated firewall")
		} else {
			if resp == nil || resp.StatusCode != http.StatusNotFound {
				return fmt.Errorf("could not update firewall: %v", err)
			}
			currentFirewall, err = fm.createFirewall(ctx, fr)
			if err != nil {
				return fmt.Errorf("could not create firewall: %v", err)
			}
			klog.Info("successfully created firewall")
		}
		fm.fwCache.updateCache(currentFirewall)
		return nil
	}

	// Check if the target firewall ID exists. In the case that CCM first starts up and the
	// firewall ID does not exist yet, check the API and see if a firewall by the right name
	// already exists.
	if targetFirewall == nil {
		currentFirewall, err := fm.Get(ctx)
		if err != nil {
			return fmt.Errorf("failed to check if firewall already exists: %s", err)
		}
		if currentFirewall == nil {
			klog.Info("existing firewall not found, need to create one")
			currentFirewall, err = fm.createFirewall(ctx, fr)
			if err != nil {
				return err
			}
			klog.Info("successfully created firewall")
		} else {
			klog.Info("existing firewall found, need to update it")
			currentFirewall, _, err = fm.updateFirewall(ctx, currentFirewall.ID, fr)
			if err != nil {
				return fmt.Errorf("could not update firewall: %v", err)
			}
			klog.Info("successfully updated firewall")
		}
		fm.fwCache.updateCache(currentFirewall)
	}
	return nil
}

func firewallDiff(targetFirewall *godo.Firewall, fr *godo.FirewallRequest) string {
	type firewallCompare struct {
		Name          string
		InboundRules  []godo.InboundRule
		OutboundRules []godo.OutboundRule
		Tags          []string
	}

	fwComp1 := firewallCompare{
		Name:          targetFirewall.Name,
		InboundRules:  targetFirewall.InboundRules,
		OutboundRules: targetFirewall.OutboundRules,
		Tags:          targetFirewall.Tags,
	}
	fwComp2 := firewallCompare{
		Name:          fr.Name,
		InboundRules:  fr.InboundRules,
		OutboundRules: fr.OutboundRules,
		Tags:          fr.Tags,
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
		if pr1 == "" || pr1 == "0" || pr1 == "all" {
			pr1 = "0"
		}
		if pr2 == "" || pr2 == "0" || pr2 == "all" {
			pr2 = "0"
		}

		return pr1 == pr2
	}))

	ruleDetailsFilter := cmp.FilterPath(func(p cmp.Path) bool {
		if strings.HasPrefix(p.String(), "InboundRules.Sources") || strings.HasPrefix(p.String(), "OutboundRules.Destinations") {
			return p.Last().String() != ".Addresses"
		}

		return false
	}, cmp.Ignore())

	return cmp.Diff(fwComp1, fwComp2, sorter, portRangeFilter, ruleDetailsFilter)
}

func isDiff(targetFirewall *godo.Firewall, fr *godo.FirewallRequest) (bool, []string) {
	var unequalParts []string
	if targetFirewall.Name != fr.Name {
		unequalParts = append(unequalParts, "name")
	}
	if diff := cmp.Diff(targetFirewall.InboundRules, fr.InboundRules,
		cmp.Transformer("inboundrule", func(r godo.InboundRule) string {
			return printInboundRule(r)
		}),
		cmpopts.SortSlices(func(r1, r2 string) bool {
			return r1 < r2
		}),
	); diff != "" {
		unequalParts = append(unequalParts, diff)
	}
	if diff := cmp.Diff(targetFirewall.OutboundRules, fr.OutboundRules,
		cmp.Transformer("outboundrule", func(r godo.OutboundRule) string {
			transformed := printOutboundRule(r)
			klog.Infof("=========== transformed outbound rule: %s", transformed)
			return transformed
		}),
		cmpopts.SortSlices(func(r1, r2 string) bool {
			return r1 < r2
		}),
	); diff != "" {
		unequalParts = append(unequalParts, diff)
	}
	if diff := cmp.Diff(targetFirewall.Tags, fr.Tags, cmpopts.SortSlices(func(t1, t2 string) bool {
		return t1 < t2
	})); diff != "" {
		unequalParts = append(unequalParts, diff)
	}
	return len(unequalParts) == 0, unequalParts
}

func (fm *firewallManager) createFirewall(ctx context.Context, fr *godo.FirewallRequest) (*godo.Firewall, error) {
	var (
		code   int
		method string
	)
	// The ObserverFunc gets called by the deferred ObserveDuration. The
	// method and code values will be set before ObserveDuration is called
	// with the value returned from the response from the Firewall API request.
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		fm.metrics.apiRequestDuration.With(prometheus.Labels{"method": method, "code": strconv.FormatInt(int64(code), 10)}).Observe(v)
	}))
	defer timer.ObserveDuration()

	klog.Infof("submitting firewall create request: %s", printRelevantFirewallRequestParts(fr))
	currentFirewall, resp, err := fm.client.Firewalls.Create(ctx, fr)
	if resp != nil {
		code = resp.StatusCode
		if resp.Request != nil {
			method = resp.Request.Method
		}
	}

	return currentFirewall, err
}

func (fm *firewallManager) updateFirewall(ctx context.Context, fwID string, fr *godo.FirewallRequest) (*godo.Firewall, *godo.Response, error) {
	var (
		code   int
		method string
	)
	// The ObserverFunc gets called by the deferred ObserveDuration. The
	// method and code values will be set before ObserveDuration is called
	// with the value returned from the response from the Firewall API request.
	timer := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		fm.metrics.apiRequestDuration.With(prometheus.Labels{"method": method, "code": strconv.FormatInt(int64(code), 10)}).Observe(v)
	}))
	defer timer.ObserveDuration()

	klog.Infof("submitting firewall update request: %s", printRelevantFirewallRequestParts(fr))
	currentFirewall, resp, err := fm.client.Firewalls.Update(ctx, fwID, fr)
	if resp != nil {
		code = resp.StatusCode
		if resp.Request != nil {
			method = resp.Request.Method
		}
	}

	return currentFirewall, resp, err
}

// createReconciledFirewallRequest creates a firewall request that has the correct rules, name and tag
func (fc *FirewallController) createReconciledFirewallRequest(serviceList []*v1.Service) *godo.FirewallRequest {
	var nodePortInboundRules []godo.InboundRule
	for _, svc := range serviceList {
		if svc.Spec.Type == v1.ServiceTypeNodePort {
			// this is a nodeport service so we should check for existing inbound rules on all ports.
			for _, servicePort := range svc.Spec.Ports {
				// In the odd case that a failure is asynchronous causing the NodePort to be set to zero.
				if servicePort.NodePort == 0 {
					klog.Warning("NodePort on the service is set to zero")
					continue
				}
				var protocol string
				switch servicePort.Protocol {
				case v1.ProtocolTCP:
					protocol = "tcp"
				case v1.ProtocolUDP:
					protocol = "udp"
				default:
					klog.Warningf("unsupported service protocol %v, skipping service port %v", servicePort.Protocol, servicePort.Name)
					continue
				}

				nodePortInboundRules = append(nodePortInboundRules,
					godo.InboundRule{
						Protocol:  protocol,
						PortRange: strconv.Itoa(int(servicePort.NodePort)),
						Sources: &godo.Sources{
							Addresses: []string{"0.0.0.0/0", "::/0"},
						},
					},
				)
			}
		}
	}
	return &godo.FirewallRequest{
		Name:          fc.workerFirewallName,
		InboundRules:  nodePortInboundRules,
		OutboundRules: allowAllOutboundRules,
		Tags:          fc.workerFirewallTags,
	}
}

func (fc *FirewallController) ensureReconciledFirewall(ctx context.Context) error {
	serviceList, err := fc.serviceLister.List(labels.Everything())
	if err != nil {
		return fmt.Errorf("failed to list services: %v", err)
	}
	fr := fc.createReconciledFirewallRequest(serviceList)
	err = fc.fwManager.Set(ctx, fr)
	if err != nil {
		return fmt.Errorf("failed to set reconciled firewall: %v", err)
	}
	return nil
}

func (fc *firewallCache) getCachedFirewall() *godo.Firewall {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return fc.firewall
}

func (fc *firewallCache) isEqual(fw *godo.Firewall) bool {
	fc.mu.RLock()
	defer fc.mu.RUnlock()
	return cmp.Equal(fc.firewall, fw)
}

func (fc *firewallCache) updateCache(currentFirewall *godo.Firewall) {
	fc.mu.Lock()
	defer fc.mu.Unlock()
	fc.firewall = currentFirewall
	klog.Infof("updated cached firewall to: %s", printRelevantFirewallParts(currentFirewall))
}

func (fc *FirewallController) observeReconcileDuration(ctx context.Context, origin string) error {
	labels := prometheus.Labels{"reconcile_type": origin}
	t := prometheus.NewTimer(fc.fwManager.metrics.reconcileDuration.With(labels))
	defer t.ObserveDuration()

	return fc.ensureReconciledFirewall(ctx)
}

func (fc *FirewallController) observeRunLoopDuration(ctx context.Context) error {
	labels := prometheus.Labels{"success": "false"}
	t := prometheus.NewTimer(prometheus.ObserverFunc(func(v float64) {
		fc.fwManager.metrics.runLoopDuration.With(labels).Observe(v)
	}))
	defer t.ObserveDuration()

	err := fc.reconcileCloudFirewallChanges(ctx)
	if err == nil || ctx.Err() != nil {
		labels["success"] = "true"
	}

	return err
}

func printRelevantFirewallParts(fw *godo.Firewall) string {
	return printFirewallParts(fw.Name, fw.InboundRules, fw.OutboundRules, fw.Tags)
}

func printRelevantFirewallRequestParts(fr *godo.FirewallRequest) string {
	return printFirewallParts(fr.Name, fr.InboundRules, fr.OutboundRules, fr.Tags)
}

func printFirewallParts(name string, inboundRules []godo.InboundRule, outboundRules []godo.OutboundRule, tags []string) string {
	parts := []string{fmt.Sprintf("Name:%s", name)}
	parts = append(parts, fmt.Sprintf("inRules:{%s}", printInboundRules(inboundRules)))
	parts = append(parts, fmt.Sprintf("outRules:{%s}", printOutboundRules(outboundRules)))
	parts = append(parts, fmt.Sprintf("Tags:%s", tags))

	return strings.Join(parts, " ")
}

func printInboundRules(inboundRules []godo.InboundRule) string {
	inbRules := make([]string, 0, len(inboundRules))
	for _, inbRule := range inboundRules {
		inbRules = append(inbRules, printInboundRule(inbRule))
	}
	sort.Strings(inbRules)
	return strings.Join(inbRules, " ")
}

func printInboundRule(inboundRule godo.InboundRule) string {
	portRange := inboundRule.PortRange
	if inboundRule.PortRange == "" || inboundRule.PortRange == "all" {
		portRange = "0"
	}
	rule := fmt.Sprintf("<Proto:%s PortRange:%s", inboundRule.Protocol, portRange)

	if inboundRule.Sources != nil {
		rule += fmt.Sprintf(" AddrSources:%s", inboundRule.Sources.Addresses)
	}

	rule += ">"
	return rule
}

func printOutboundRules(outboundRules []godo.OutboundRule) string {
	outbRules := make([]string, 0, len(outboundRules))
	for _, outbRule := range outboundRules {
		outbRules = append(outbRules, printOutboundRule(outbRule))
	}
	sort.Strings(outbRules)
	return strings.Join(outbRules, " ")
}

func printOutboundRule(outboundRule godo.OutboundRule) string {
	portRange := outboundRule.PortRange
	if outboundRule.PortRange == "" || outboundRule.PortRange == "all" {
		portRange = "0"
	}
	rule := fmt.Sprintf("<Proto:%s PortRange:%s", outboundRule.Protocol, portRange)

	if outboundRule.Destinations != nil {
		rule += fmt.Sprintf(" AddrDestinations:%s", outboundRule.Destinations.Addresses)
	}

	rule += ">"
	return rule
}
