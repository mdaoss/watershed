// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Watershed

// A minimal, read-only IdentityAllocator backed by CiliumIdentity CRDs.
// It can run in a dedicated Cilium-EgressGateway pod alongside cilium-agent.

package idallocator

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"

	ciliumv2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	k8sClient "github.com/cilium/cilium/pkg/k8s/client"
	ciliumInformers "github.com/cilium/cilium/pkg/k8s/client/informers/externalversions"

	identitypkg "github.com/cilium/cilium/pkg/identity"
	identitycache "github.com/cilium/cilium/pkg/identity/cache"
	labelspkg "github.com/cilium/cilium/pkg/labels"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
)

// ──────────────────────────────────────────────────────────────────────────────
// Allocator structure
// ──────────────────────────────────────────────────────────────────────────────

type CRDIdentityAllocator struct {
	identitiesByID     map[identitypkg.NumericIdentity]*identitypkg.Identity
	identitiesByLabels map[string]*identitypkg.Identity
	mu                 sync.RWMutex
	initialSyncDone    chan struct{}
}

// NewCRDIdentityAllocator watches all CiliumIdentity CRDs using the Cilium
// typed client contained in k8s/client.Clientset.  It blocks until the first
// full list has been processed or stopCh is closed.
func NewCRDIdentityAllocator(clientset *k8sClient.Clientset, stopCh <-chan struct{}) (*CRDIdentityAllocator, error) {
	alloc := &CRDIdentityAllocator{
		identitiesByID:     map[identitypkg.NumericIdentity]*identitypkg.Identity{},
		identitiesByLabels: map[string]*identitypkg.Identity{},
		initialSyncDone:    make(chan struct{}),
	}

	// Build a SharedInformerFactory **for Cilium CRDs only**.
	ciliumFactory := ciliumInformers.NewSharedInformerFactory(
		*clientset, 0) // 0 == no resync

	// Grab the CiliumIdentity informer (cluster‑scoped object).
	identityInformer := ciliumFactory.Cilium().V2().CiliumIdentities().Informer()

	identityInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			alloc.handleAddUpdate(obj.(*ciliumv2.CiliumIdentity))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			oldCI := oldObj.(*ciliumv2.CiliumIdentity)
			newCI := newObj.(*ciliumv2.CiliumIdentity)
			if !equalLabelSets(oldCI.SecurityLabels, newCI.SecurityLabels) {
				alloc.handleDelete(oldCI)
			}
			alloc.handleAddUpdate(newCI)
		},
		DeleteFunc: func(obj interface{}) {
			ci, ok := obj.(*ciliumv2.CiliumIdentity)
			if !ok {
				// DeletedFinalStateUnknown
				tomb, _ := obj.(cache.DeletedFinalStateUnknown)
				ci, _ = tomb.Obj.(*ciliumv2.CiliumIdentity)
			}
			alloc.handleDelete(ci)
		},
	})

	// Start the factory / informer.
	ciliumFactory.Start(stopCh)

	// Wait for the cache to be in sync.
	if ok := cache.WaitForCacheSync(stopCh, identityInformer.HasSynced); !ok {
		return nil, fmt.Errorf("failed to sync CiliumIdentity informer cache")
	}
	close(alloc.initialSyncDone)
	return alloc, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Informer event helpers
// ──────────────────────────────────────────────────────────────────────────────

func (alloc *CRDIdentityAllocator) handleAddUpdate(ci *ciliumv2.CiliumIdentity) {
	idNum, err := strconv.ParseUint(ci.Name, 10, 32)
	if err != nil {
		return // malformed name
	}
	nid := identitypkg.NumericIdentity(idNum)

	// Convert SecurityLabels map[string]string -> labels.Labels
	lbls := labelspkg.Labels{}
	for k, v := range ci.SecurityLabels {
		lbl := labelspkg.ParseLabel(k)
		lbl.Value = v
		lbls[lbl.Key] = lbl
	}

	cid := identitypkg.NewIdentity(nid, lbls)

	alloc.mu.Lock()
	defer alloc.mu.Unlock()
	alloc.identitiesByID[nid] = cid
	alloc.identitiesByLabels[makeLabelSetKey(ci.SecurityLabels)] = cid
}

func (alloc *CRDIdentityAllocator) handleDelete(ci *ciliumv2.CiliumIdentity) {
	idNum, err := strconv.ParseUint(ci.Name, 10, 32)
	if err != nil {
		return
	}
	nid := identitypkg.NumericIdentity(idNum)
	key := makeLabelSetKey(ci.SecurityLabels)

	alloc.mu.Lock()
	defer alloc.mu.Unlock()
	delete(alloc.identitiesByID, nid)
	delete(alloc.identitiesByLabels, key)
}

// ──────────────────────────────────────────────────────────────────────────────
// identity/cache.IdentityAllocator interface
// ──────────────────────────────────────────────────────────────────────────────

// Wait until first list is done.
func (alloc *CRDIdentityAllocator) WaitForInitialGlobalIdentities(ctx context.Context) error {
	select {
	case <-alloc.initialSyncDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (alloc *CRDIdentityAllocator) LookupIdentity(_ context.Context, lbls labelspkg.Labels) *identitypkg.Identity {
	sec := map[string]string{}
	for _, l := range lbls {
		src := l.Source
		if src == "" {
			src = labelspkg.LabelSourceK8s
		}
		sec[src+":"+l.Key] = l.Value
	}
	key := makeLabelSetKey(sec)

	alloc.mu.RLock()
	defer alloc.mu.RUnlock()
	return alloc.identitiesByLabels[key]
}

func (alloc *CRDIdentityAllocator) LookupIdentityByID(_ context.Context, id identitypkg.NumericIdentity) *identitypkg.Identity {
	alloc.mu.RLock()
	defer alloc.mu.RUnlock()
	return alloc.identitiesByID[id]
}

func (alloc *CRDIdentityAllocator) AllocateIdentity(_ context.Context, lbls labelspkg.Labels, _ bool, _ identitypkg.NumericIdentity) (*identitypkg.Identity, bool, error) {
	if id := alloc.LookupIdentity(context.Background(), lbls); id != nil {
		return id, false, nil
	}
	return nil, false, fmt.Errorf("identity not found (read‑only allocator)")
}

func (alloc *CRDIdentityAllocator) Release(_ context.Context, _ *identitypkg.Identity, _ bool) (bool, error) {
	return false, nil // noop
}
func (alloc *CRDIdentityAllocator) ReleaseSlice(_ context.Context, _ []*identitypkg.Identity) error {
	return nil
}

func (alloc *CRDIdentityAllocator) GetIdentityCache() identitypkg.IdentityMap {
	alloc.mu.RLock()
	defer alloc.mu.RUnlock()
	out := make(identitypkg.IdentityMap, len(alloc.identitiesByID))
	for id, ident := range alloc.identitiesByID {
		out[id] = ident.LabelArray
	}
	return out
}
func (alloc *CRDIdentityAllocator) GetIdentities() identitycache.IdentitiesModel {
	return identitycache.IdentitiesModel{}.FromIdentityCache(alloc.GetIdentityCache())
}

func (alloc *CRDIdentityAllocator) AllocateCIDRsForIPs(_ []net.IP, _ map[netip.Prefix]*identitypkg.Identity) ([]*identitypkg.Identity, error) {
	return nil, fmt.Errorf("CIDR identities not supported")
}
func (alloc *CRDIdentityAllocator) ReleaseCIDRIdentitiesByID(_ context.Context, _ []identitypkg.NumericIdentity) error {
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// Observe ‑‑ new in recent Cilium; here we provide a *no‑op* implementation
// ──────────────────────────────────────────────────────────────────────────────

func (alloc *CRDIdentityAllocator) Observe(ctx context.Context, next func(identitycache.IdentityChange), complete func(error)) {
}

func (m *CRDIdentityAllocator) UnwithholdLocalIdentities(nids []identitypkg.NumericIdentity) {}
func (m *CRDIdentityAllocator) WithholdLocalIdentities(nids []identitypkg.NumericIdentity)   {}

// ──────────────────────────────────────────────────────────────────────────────
// Utility helpers
// ──────────────────────────────────────────────────────────────────────────────

func makeLabelSetKey(sec map[string]string) string {
	if len(sec) == 0 {
		return ""
	}
	keys := make([]string, 0, len(sec))
	for k := range sec {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	for _, k := range keys {
		b.WriteString(k)
		b.WriteString("=")
		b.WriteString(sec[k])
		b.WriteString(";")
	}
	return b.String()
}

func equalLabelSets(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// ──────────────────────────────────────────────────────────────────────────────
// Minimal CRD type for completeness (only what we access).
// If you already import ciliumv2, you can delete this block.
// ──────────────────────────────────────────────────────────────────────────────

// ensure we reference metav1 so goimports keeps it.
var _ = metav1.TypeMeta{}
