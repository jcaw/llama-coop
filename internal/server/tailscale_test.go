package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/mostlygeek/llama-swap/internal/config"
	"github.com/mostlygeek/llama-swap/internal/store"
	"github.com/mostlygeek/llama-swap/internal/store/sqlite"
	"github.com/mostlygeek/llama-swap/internal/tailcat"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/tailcfg"
)

func tailscaleTestIdentity(name string) *apitype.WhoIsResponse {
	return &apitype.WhoIsResponse{
		Node:        &tailcfg.Node{Name: "different.example.ts.net.", Hostinfo: (&tailcfg.Hostinfo{Hostname: name + "-laptop"}).View()},
		UserProfile: &tailcfg.UserProfile{ID: 1, LoginName: "different@example.com", DisplayName: name},
	}
}

func TestServer_TailscaleIdentity(t *testing.T) {
	alice := tailscaleTestIdentity("Alice")
	alice.UserProfile.ID = 9007199254740993
	tagged := tailscaleTestIdentity("Alice")
	tagged.Node.Tags = []string{"tag:worker"}
	for _, tc := range []struct {
		name, remote, user, device     string
		who                            *apitype.WhoIsResponse
		disabled, virtual, trackDevice bool
		calls                          int32
	}{
		{name: "IPv4", calls: 1, remote: "100.64.0.1:1234", who: alice, user: "Alice"},
		{name: "IPv6", calls: 1, remote: "[fd7a:115c:a1e0::1]:1234", who: alice, user: "Alice"},
		{name: "mapped IPv4", calls: 1, remote: "[::ffff:100.64.0.1]:1234", who: alice, user: "Alice"},
		{name: "device tracking enabled", calls: 1, remote: "100.64.0.1:1234", who: alice, user: "Alice", device: "Alice-laptop", trackDevice: true},
		{name: "disabled", remote: "100.64.0.1:1234", who: alice, disabled: true},
		{name: "Tailcat", remote: "100.64.0.1:1234", who: alice, virtual: true},
		{name: "LAN", remote: "192.168.0.10:1234", who: alice},
		{name: "tagged", calls: 1, remote: "100.64.0.1:1234", who: tagged, device: "Alice-laptop", trackDevice: true},
		{name: "missing hostname", trackDevice: true, calls: 1, remote: "100.64.0.1:1234", who: &apitype.WhoIsResponse{Node: &tailcfg.Node{Name: alice.Node.Name}, UserProfile: alice.UserProfile}, user: "Alice"},
		{name: "timeout", calls: 1, remote: "100.64.0.1:1234"},
	} {
		for _, path := range []string{"/v1/chat/completions", "/upstream/m1/v1/chat/completions"} {
			t.Run(tc.name+path, func(t *testing.T) {
				local := newStubRouter([]string{"m1"}, "{}")
				s := newTestServerWithConfig(config.Config{Tailscale: config.TailscaleConfig{Enabled: !tc.disabled, TrackDevice: tc.trackDevice}, Models: map[string]config.ModelConfig{"m1": {}}}, local, newStubRouter(nil, ""))
				t.Cleanup(func() { s.Shutdown(time.Second); s.store.Close() })
				var calls atomic.Int32
				if r := s.inflight.tailscale; r != nil {
					r.whois = func(ctx context.Context, address string) (*apitype.WhoIsResponse, error) {
						calls.Add(1)
						assert.Equal(t, netip.MustParseAddrPort(tc.remote).Addr().Unmap().String(), address)
						if tc.who == nil {
							<-ctx.Done()
							return nil, ctx.Err()
						}
						return tc.who, nil
					}
				}
				check := func(metadata map[string]string) {
					assert.Equal(t, tc.user, metadata["tailscale_name"])
					assert.Equal(t, tc.device, metadata["tailscale_hostname"])
					assert.NotContains(t, metadata, "tailscale_login")
					if tc.user != "" {
						assert.Equal(t, "9007199254740993", metadata["tailscale_user_id"])
					} else {
						assert.NotContains(t, metadata, "tailscale_user_id")
					}
					if !tc.trackDevice {
						assert.NotContains(t, metadata, "tailscale_hostname")
					}
				}
				local.serveHTTP = func(w http.ResponseWriter, _ *http.Request) {
					check(s.inflight.Current().Requests[0].Metadata)
					w.Write([]byte("{}"))
				}
				for range 2 {
					req := chatRequest("m1")
					req.URL.Path, req.RemoteAddr = path, tc.remote
					if tc.virtual {
						req = req.WithContext(tailcat.ContextWithNodeKey(req.Context(), "nodekey:test"))
					}
					req.Header.Set("Tailscale-User-Name", "Mallory")
					req.Header.Set("X-Forwarded-For", "100.64.0.2")
					rec := httptest.NewRecorder()
					s.ServeHTTP(rec, req)
					require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
				}
				entries := metricsEntries(t, s.metrics)
				require.Len(t, entries, 2)
				for _, entry := range entries {
					check(entry.Metadata)
				}
				assert.Equal(t, tc.calls, calls.Load())
			})
		}
	}
}

func TestServer_TailscaleLookupCache(t *testing.T) {
	r := newTailscaleResolver(context.Background(), nil, nil)
	t.Cleanup(r.close)
	var calls atomic.Int32
	started, release := make(chan struct{}), make(chan struct{})
	r.whois = func(context.Context, string) (*apitype.WhoIsResponse, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
		}
		return tailscaleTestIdentity("Alice"), nil
	}
	peer := netip.MustParseAddr("100.64.0.1")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan map[string]string, 1)
	go func() { done <- r.resolve(ctx, peer) }()
	<-started
	cancel()
	require.Nil(t, <-done)
	ready := make(chan map[string]string, 1)
	go func() { ready <- r.resolve(context.Background(), peer) }()
	select {
	case <-ready:
		close(release)
		t.Fatal("second caller did not wait for the shared lookup")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	assert.Equal(t, "Alice", (<-ready)["tailscale_name"])
	assert.Equal(t, int32(1), calls.Load())
}

func TestServer_TailscaleCacheLifecycle(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(map[bool]string{false: "refresh", true: "failed refresh"}[fail], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "activity.sqlite")
			st, err := sqlite.New(path)
			require.NoError(t, err)
			t.Cleanup(func() { st.Close() })
			r := newTailscaleResolver(context.Background(), st.Cache(), nil)
			t.Cleanup(r.close)
			r.whois = func(context.Context, string) (*apitype.WhoIsResponse, error) {
				return tailscaleTestIdentity("Alice"), nil
			}
			peer := netip.MustParseAddr("100.64.0.1")
			key := tailscaleCachePrefix + peer.String()
			require.NoError(t, st.Cache().Set(context.Background(), store.CacheEntry{Key: key, Data: []byte("{")}))
			snapshot := r.resolve(context.Background(), peer)
			require.Equal(t, "Alice", snapshot["tailscale_name"])
			saved, found, err := st.Cache().Get(context.Background(), key)
			require.NoError(t, err)
			require.True(t, found)
			assert.Zero(t, saved.TTL)
			r.cache.MaxEntries = 1
			r.resolve(context.Background(), peer.Next())
			_, found = r.cache.PeekOk(peer)
			require.False(t, found)
			r.close()
			require.NoError(t, st.Close())
			st, err = sqlite.New(path)
			require.NoError(t, err)
			r = newTailscaleResolver(context.Background(), st.Cache(), nil)
			t.Cleanup(r.close)
			r.whois = func(context.Context, string) (*apitype.WhoIsResponse, error) {
				t.Error("fresh saved identity triggered a lookup")
				return nil, errors.New("unexpected lookup")
			}
			assert.Equal(t, snapshot, r.resolve(context.Background(), peer))
			saved.Timestamp = time.Now().Add(-2 * tailscaleRefreshInterval).Truncate(time.Second)
			require.NoError(t, st.Cache().Set(context.Background(), saved))
			r.cache.Delete(peer)
			started, release := make(chan struct{}), make(chan struct{})
			var calls atomic.Int32
			r.whois = func(context.Context, string) (*apitype.WhoIsResponse, error) {
				calls.Add(1)
				close(started)
				<-release
				if fail {
					return nil, errors.New("daemon unavailable")
				}
				who := tailscaleTestIdentity("Bob")
				who.UserProfile.ID = 2
				return who, nil
			}
			assert.Equal(t, snapshot, r.resolve(context.Background(), peer))
			<-started
			assert.Equal(t, snapshot, r.resolve(context.Background(), peer))
			close(release)
			r.flights.Do(peer.String(), func() (any, error) { return nil, nil })
			want, interval := "Bob", tailscaleRefreshInterval
			if fail {
				want, interval = "Alice", tailscaleRetryInterval
			}
			assert.Equal(t, want, r.resolve(context.Background(), peer)["tailscale_name"])
			assert.WithinDuration(t, time.Now().Add(interval), r.cache.Get(peer).refreshAfter, time.Second)
			assert.Equal(t, int32(1), calls.Load())
			assert.Equal(t, "Alice", snapshot["tailscale_name"])
			after, _, err := st.Cache().Get(context.Background(), key)
			require.NoError(t, err)
			if fail {
				assert.Equal(t, saved, after)
			} else {
				assert.Contains(t, string(after.Data), "Bob")
			}
			r.whois = func(context.Context, string) (*apitype.WhoIsResponse, error) {
				calls.Add(1)
				return tailscaleTestIdentity("Alice"), nil
			}
			assert.Equal(t, "Alice", r.resolve(context.Background(), peer.Next().Next())["tailscale_name"])
			require.NoError(t, st.Close())
			r.cache.Delete(peer)
			assert.Equal(t, "Alice", r.resolve(context.Background(), peer)["tailscale_name"])
			assert.Equal(t, "Alice", r.resolve(context.Background(), peer)["tailscale_name"])
			assert.Equal(t, int32(3), calls.Load(), "failed store writes must retain the RAM identity")
		})
	}
}

func TestServer_TailscaleShutdown(t *testing.T) {
	s := newTestServerWithConfig(config.Config{Tailscale: config.TailscaleConfig{Enabled: true}}, newStubRouter(nil, ""), newStubRouter(nil, ""))
	r := s.inflight.tailscale
	t.Cleanup(func() { r.close(); s.store.Close() })
	started, canceled, release := make(chan struct{}), make(chan struct{}), make(chan struct{})
	r.whois = func(ctx context.Context, _ string) (*apitype.WhoIsResponse, error) {
		close(started)
		<-ctx.Done()
		close(canceled)
		<-release
		return nil, ctx.Err()
	}
	peer := netip.MustParseAddr("100.64.0.1")
	go r.resolve(context.Background(), peer)
	<-started
	done := make(chan error, 1)
	go func() { done <- s.Shutdown(time.Second) }()
	<-canceled
	select {
	case <-done:
		close(release)
		t.Fatal("shutdown returned before its lookup finished")
	case <-time.After(50 * time.Millisecond):
	}
	close(release)
	require.NoError(t, <-done)
	r.whois = func(context.Context, string) (*apitype.WhoIsResponse, error) {
		t.Error("lookup after shutdown")
		return nil, errors.New("closed")
	}
	r.lookup(peer.Next(), tailscaleCacheEntry{}) // A callback queued before shutdown can enter afterward.
}

func TestServer_TailscaleStableNames(t *testing.T) {
	path := filepath.Join(t.TempDir(), "activity.sqlite")
	st, err := sqlite.New(path)
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })
	peer := netip.MustParseAddr("100.64.1.1")
	cases := []struct {
		id            tailcfg.UserID
		display, want string
	}{
		{1, "Alex", "Alex"},
		{2, "Alex", "Alex [2]"},
		{2, "Renamed", "Alex [2]"},
		{3, " alex ", "alex [3]"},
		{4, "Alex [2]", "Alex [2] [4]"},
		{5, "Pat Lee", "Pat Lee"},
		{6, "Pat Lee", "Pat L."},
		{7, "Pat Lee", "Pat L. [7]"},
		{8, "", "User [8]"},
		{9, "Émile 李", "Émile 李"},
		{10, "Émile 李", "Émile 李."},
		{9007199254740993, "Alex", "Alex [9007199254740993]"},
		{0, "Unknown", ""},
	}
	for pass := range 2 {
		r := newTailscaleResolver(context.Background(), st.Cache(), nil)
		t.Cleanup(r.close)
		if pass == 0 {
			require.NoError(t, st.Cache().Set(context.Background(), store.CacheEntry{Key: tailscaleNamesKey, Data: []byte(`{"1":"Old","2":broken}`)}))
			_, err := r.userName(context.Background(), &tailcfg.UserProfile{ID: 1, DisplayName: "Alex"})
			require.Error(t, err)
			require.Nil(t, r.names, "a corrupt registry must not publish partially decoded labels")
			require.NoError(t, st.Cache().Delete(context.Background(), tailscaleNamesKey))
		}
		for _, tc := range cases {
			r.whois = func(context.Context, string) (*apitype.WhoIsResponse, error) {
				who := tailscaleTestIdentity(tc.display)
				who.UserProfile.ID = tc.id
				return who, nil
			}
			assert.Equal(t, tc.want, r.resolve(context.Background(), peer)["tailscale_name"])
			peer = peer.Next() // A new device must reuse its owner's label, including after restart.
		}
		require.NoError(t, st.Close())
		if pass == 0 {
			name, err := r.userName(context.Background(), &tailcfg.UserProfile{ID: 99, DisplayName: "Alex"})
			assert.Empty(t, name, "a failed write must not publish an unreserved label")
			assert.Error(t, err)
		}
		r.close()
		st, err = sqlite.New(path)
		require.NoError(t, err)
		slices.Reverse(cases) // Returning devices must not change who owns an assigned label.
	}
}

func TestServer_TailscaleConcurrentNames(t *testing.T) {
	st, err := sqlite.New("")
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })
	r := newTailscaleResolver(context.Background(), st.Cache(), nil)
	t.Cleanup(r.close)
	labels := make([]string, 16)
	var wg sync.WaitGroup
	for i := range labels {
		wg.Go(func() {
			name, err := r.userName(context.Background(), &tailcfg.UserProfile{ID: tailcfg.UserID(i + 1), DisplayName: "Alex"})
			assert.NoError(t, err)
			labels[i] = name
		})
	}
	wg.Wait()
	unique := make(map[string]bool)
	for _, name := range labels {
		unique[name] = true
	}
	assert.Len(t, unique, len(labels), "concurrent people must not share a label")
	saved, found, err := st.Cache().Get(context.Background(), tailscaleNamesKey)
	require.NoError(t, err)
	require.True(t, found)
	var persisted map[tailcfg.UserID]string
	require.NoError(t, json.Unmarshal(saved.Data, &persisted))
	assert.Equal(t, r.names, persisted, "concurrent allocations must not overwrite saved people")
}

func TestServer_TailscaleDeviceTracking(t *testing.T) {
	st, err := sqlite.New(filepath.Join(t.TempDir(), "activity.sqlite"))
	require.NoError(t, err)
	t.Cleanup(func() { st.Close() })
	peer := netip.MustParseAddr("100.64.0.1")
	require.NoError(t, st.Cache().Set(context.Background(), store.CacheEntry{
		Key:  "tailscale-identity:v2:" + peer.String(),
		Data: []byte(`{"tailscale_name":"Old","tailscale_hostname":"old-laptop"}`), Timestamp: time.Now(),
	}))
	for _, track := range []bool{true, false, true, false} {
		r := newTailscaleResolver(context.Background(), st.Cache(), nil)
		r.trackDevice = track
		r.whois = func(context.Context, string) (*apitype.WhoIsResponse, error) {
			return tailscaleTestIdentity("Alice"), nil
		}
		metadata := r.resolve(context.Background(), peer)
		assert.Equal(t, "Alice", metadata["tailscale_name"])
		assert.Equal(t, "1", metadata["tailscale_user_id"])
		key := tailscaleCachePrefix + peer.String()
		if track {
			key += ":device"
			assert.Equal(t, "Alice-laptop", metadata["tailscale_hostname"])
		} else {
			assert.NotContains(t, metadata, "tailscale_hostname")
		}
		saved, found, err := st.Cache().Get(context.Background(), key)
		require.NoError(t, err)
		require.True(t, found)
		var persisted map[string]string
		require.NoError(t, json.Unmarshal(saved.Data, &persisted))
		assert.Equal(t, metadata, persisted)
		r.close()
	}
}
