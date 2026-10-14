package server

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/mostlygeek/llama-swap/internal/logmon"
	"github.com/mostlygeek/llama-swap/internal/store"
	"github.com/mostlygeek/llama-swap/internal/swaputil"
	"github.com/mostlygeek/llama-swap/internal/tailcat"
	"golang.org/x/sync/singleflight"
	"tailscale.com/client/local"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/util/lru"
)

const (
	tailscaleLookupTimeout   = 500 * time.Millisecond
	tailscaleRefreshInterval = time.Hour
	tailscaleRetryInterval   = 5 * time.Second
	tailscaleCachePrefix     = "tailscale-identity:v3:"
	tailscaleNamesKey        = "tailscale-user-names:v1"
)

type tailscaleCacheEntry struct {
	metadata     map[string]string // Immutable snapshots; refresh replaces the map.
	refreshAfter time.Time
}

type tailscaleResolver struct {
	trackDevice bool
	whois       func(context.Context, string) (*apitype.WhoIsResponse, error)
	ctx         context.Context
	cancel      context.CancelFunc
	disk        store.CacheRepository
	logger      *logmon.Monitor
	mu          sync.Mutex
	cache       lru.Cache[netip.Addr, tailscaleCacheEntry]
	flights     singleflight.Group
	namesMu     sync.Mutex
	names       map[tailcfg.UserID]string
	work        sync.RWMutex // Lookups hold RLock; shutdown waits with Lock.
}

func newTailscaleResolver(ctx context.Context, disk store.CacheRepository, logger *logmon.Monitor) *tailscaleResolver {
	ctx, cancel := context.WithCancel(ctx)
	return &tailscaleResolver{
		whois: new(local.Client).WhoIs, ctx: ctx, cancel: cancel,
		disk: disk, logger: logger, cache: lru.Cache[netip.Addr, tailscaleCacheEntry]{MaxEntries: 64 * 1024},
	}
}

func (t *tailscaleResolver) annotate(r *http.Request) {
	data, ok := swaputil.ReadContext(r.Context())
	if !ok || data.Metadata == nil {
		return
	}
	if _, ok := tailcat.SourceFromContext(r.Context()); ok {
		return // Tailcat's virtual addresses are not tailnet device identities.
	}
	// Trust the connection address, never identity or forwarding headers.
	peer, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !tsaddr.IsTailscaleIP(peer.Addr().Unmap()) {
		return
	}
	maps.Copy(data.Metadata, t.resolve(r.Context(), peer.Addr().Unmap()))
}

func (t *tailscaleResolver) resolve(ctx context.Context, peer netip.Addr) map[string]string {
	t.mu.Lock()
	entry, _ := t.cache.GetOk(peer)
	t.mu.Unlock()
	if time.Now().Before(entry.refreshAfter) || t.ctx.Err() != nil {
		return entry.metadata
	}
	ready := t.flights.DoChan(peer.String(), func() (any, error) { return t.lookup(peer, entry), nil })
	if entry.metadata != nil {
		return entry.metadata
	}
	ctx, cancel := context.WithTimeout(ctx, tailscaleLookupTimeout)
	defer cancel()
	select {
	case result := <-ready:
		restored := result.Val.(tailscaleCacheEntry)
		if restored.metadata != nil && !time.Now().Before(restored.refreshAfter) {
			// Stale disk data is usable immediately; refresh it in the background.
			t.flights.DoChan(peer.String(), func() (any, error) { return t.lookup(peer, restored), nil })
		}
		return restored.metadata
	case <-ctx.Done():
		return nil
	}
}

func (t *tailscaleResolver) lookup(peer netip.Addr, entry tailscaleCacheEntry) tailscaleCacheEntry {
	t.work.RLock()
	defer t.work.RUnlock()
	if t.ctx.Err() != nil {
		return entry // Queued callbacks cannot touch the store after shutdown.
	}
	t.mu.Lock()
	if cached, found := t.cache.PeekOk(peer); found {
		entry = cached
	}
	t.mu.Unlock()
	if time.Now().Before(entry.refreshAfter) {
		return entry
	}
	ctx, cancel := context.WithTimeout(t.ctx, tailscaleLookupTimeout)
	defer cancel()
	defer func() {
		t.mu.Lock()
		t.cache.Set(peer, entry)
		t.mu.Unlock()
	}()
	key := tailscaleCachePrefix + peer.String()
	if t.trackDevice {
		key += ":device" // Keep device-enabled entries out of the user-only cache.
	}
	if entry.metadata == nil && t.disk != nil {
		saved, found, err := t.disk.Get(ctx, key)
		var metadata map[string]string
		if err == nil && found {
			err = json.Unmarshal(saved.Data, &metadata)
		}
		if err != nil {
			t.warn("reading identity cache: %v", err)
		} else if metadata != nil {
			entry = tailscaleCacheEntry{metadata, saved.Timestamp.Add(tailscaleRefreshInterval)}
			return entry // Publish restored data; resolve starts a separate refresh if stale.
		}
	}
	who, err := t.whois(ctx, peer.String())
	if err != nil || who == nil || who.Node == nil {
		entry.refreshAfter = time.Now().Add(tailscaleRetryInterval)
		return entry // Failed refreshes keep the last identity, including on disk.
	}
	metadata := make(map[string]string)
	if t.trackDevice && who.Node.Hostinfo.Valid() {
		metadata["tailscale_hostname"] = who.Node.Hostinfo.Hostname()
	}
	if !who.Node.IsTagged() && who.UserProfile != nil {
		name, err := t.userName(ctx, who.UserProfile)
		if err != nil {
			t.warn("assigning user name: %v", err)
			entry.refreshAfter = time.Now().Add(tailscaleRetryInterval)
			return entry
		}
		metadata["tailscale_name"] = name
		if who.UserProfile.ID > 0 {
			metadata["tailscale_user_id"] = strconv.FormatInt(int64(who.UserProfile.ID), 10)
		}
	}
	entry.metadata = metadata
	checkedAt := time.Now()
	entry.refreshAfter = checkedAt.Add(tailscaleRefreshInterval)
	if t.disk != nil {
		data, _ := json.Marshal(entry.metadata) // A string map cannot fail JSON encoding.
		// No expiry: stale identities must remain readable after a restart.
		if err := t.disk.Set(ctx, store.CacheEntry{Key: key, Data: data, Timestamp: checkedAt}); err != nil {
			t.warn("saving identity cache: %v", err)
		}
	}
	return entry
}

func (t *tailscaleResolver) userName(ctx context.Context, profile *tailcfg.UserProfile) (string, error) {
	if profile.ID <= 0 {
		return "", nil
	}
	t.namesMu.Lock()
	defer t.namesMu.Unlock()
	if t.names == nil {
		names := make(map[tailcfg.UserID]string)
		if t.disk != nil {
			saved, found, err := t.disk.Get(ctx, tailscaleNamesKey)
			if err != nil {
				return "", err
			}
			if found {
				if err := json.Unmarshal(saved.Data, &names); err != nil {
					return "", err
				}
			}
		}
		t.names = names
		if t.names == nil {
			t.names = make(map[tailcfg.UserID]string)
		}
	}
	if name, found := t.names[profile.ID]; found {
		return name, nil
	}
	used := func(candidate string) bool {
		for _, name := range t.names {
			if strings.EqualFold(candidate, name) {
				return true
			}
		}
		return false
	}
	words := strings.Fields(profile.DisplayName)
	name := strings.Join(words, " ")
	id := strconv.FormatInt(int64(profile.ID), 10)
	if name == "" {
		name = "User [" + id + "]"
	}
	if used(name) && len(words) > 1 {
		initial := []rune(words[len(words)-1])[0]
		if unicode.IsLetter(initial) {
			name = words[0] + " " + string(initial) + "."
		}
	}
	for used(name) {
		name += " [" + id + "]"
	}
	t.names[profile.ID] = name
	if t.disk != nil {
		data, _ := json.Marshal(t.names) // Integer keys and string values cannot fail JSON encoding.
		if err := t.disk.Set(ctx, store.CacheEntry{Key: tailscaleNamesKey, Data: data}); err != nil {
			t.names = nil // Reload: a canceled write might have committed before returning an error.
			return "", err
		}
	}
	return name, nil
}

func (t *tailscaleResolver) warn(format string, args ...any) {
	if t.logger != nil {
		t.logger.Warnf("tailscale: "+format, args...)
	}
}

func (t *tailscaleResolver) close() {
	if t != nil {
		t.cancel()
		t.work.Lock()
		//lint:ignore SA2001 This lock is a shutdown barrier for lookups holding RLock.
		t.work.Unlock()
	}
}
