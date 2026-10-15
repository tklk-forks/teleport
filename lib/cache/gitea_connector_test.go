/*
 * Teleport
 * Copyright (C) 2025  Gravitational, Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package cache

import (
	"context"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
)

func newGiteaConnector(t *testing.T, name string) *giteaconnectorv1.GiteaConnector {
	t.Helper()
	connector := giteaconnectorv1.GiteaConnector_builder{
		Metadata: headerv1.Metadata_builder{Name: name}.Build(),
		Spec: giteaconnectorv1.GiteaConnectorSpec_builder{
			ClientId:     "client-id",
			ClientSecret: "client-secret",
			RedirectUrl:  "https://proxy.example.com/v1/webapi/gitea/callback",
			EndpointUrl:  "https://gitea.example.com",
			TeamsToRoles: []*giteaconnectorv1.GiteaTeamRolesMapping{
				giteaconnectorv1.GiteaTeamRolesMapping_builder{
					Organization: "infra",
					Team:         "Owners",
					Roles:        []string{"access"},
				}.Build(),
			},
		}.Build(),
	}.Build()
	require.NoError(t, services.ValidateGiteaConnector(connector))
	return connector
}

// TestGiteaConnector tests that CRUD operations on Gitea connectors are
// replicated from the backend to the cache, secrets included.
func TestGiteaConnector(t *testing.T) {
	t.Parallel()

	p := newTestPack(t, ForAuth)
	t.Cleanup(p.Close)

	testResources153(t, p, testFuncs[*giteaconnectorv1.GiteaConnector]{
		newResource: func(name string) (*giteaconnectorv1.GiteaConnector, error) {
			return newGiteaConnector(t, name), nil
		},
		create: func(ctx context.Context, item *giteaconnectorv1.GiteaConnector) error {
			_, err := p.giteaConnectors.CreateGiteaConnector(ctx, item)
			return trace.Wrap(err)
		},
		list: func(ctx context.Context, pageSize int, pageToken string) ([]*giteaconnectorv1.GiteaConnector, string, error) {
			return p.giteaConnectors.ListGiteaConnectors(ctx, pageSize, pageToken, true)
		},
		cacheList: func(ctx context.Context, pageSize int, pageToken string) ([]*giteaconnectorv1.GiteaConnector, string, error) {
			return p.cache.ListGiteaConnectors(ctx, pageSize, pageToken, true)
		},
		cacheGet: func(ctx context.Context, name string) (*giteaconnectorv1.GiteaConnector, error) {
			return p.cache.GetGiteaConnector(ctx, name, true)
		},
		deleteAll: p.giteaConnectors.DeleteAllGiteaConnectors,
	})
}

func TestGiteaConnectorCacheSecrets(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	p := newTestPack(t, ForAuth)
	t.Cleanup(p.Close)

	_, err := p.giteaConnectors.CreateGiteaConnector(ctx, newGiteaConnector(t, "gitea"))
	require.NoError(t, err)

	require.EventuallyWithT(t, func(t *assert.CollectT) {
		got, err := p.cache.GetGiteaConnector(ctx, "gitea", true)
		require.NoError(t, err)
		require.Equal(t, "client-secret", got.GetSpec().GetClientSecret())
	}, 10*time.Second, 50*time.Millisecond)

	withoutSecrets, err := p.cache.GetGiteaConnector(ctx, "gitea", false)
	require.NoError(t, err)
	require.Empty(t, withoutSecrets.GetSpec().GetClientSecret())

	list, _, err := p.cache.ListGiteaConnectors(ctx, 0, "", false)
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.Empty(t, list[0].GetSpec().GetClientSecret())

	// Stripping secrets from one read must not affect the cached copy.
	again, err := p.cache.GetGiteaConnector(ctx, "gitea", true)
	require.NoError(t, err)
	require.Equal(t, "client-secret", again.GetSpec().GetClientSecret())

	require.Contains(t, ForAuth(Config{}).Watches, types.WatchKind{Kind: types.KindGitea, LoadSecrets: true})
}
