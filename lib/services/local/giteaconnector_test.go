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

package local_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/lib/backend/memory"
	"github.com/gravitational/teleport/lib/services/local"
)

func newGiteaConnector(name string) *giteaconnectorv1.GiteaConnector {
	return giteaconnectorv1.GiteaConnector_builder{
		Metadata: headerv1.Metadata_builder{Name: name}.Build(),
		Spec: giteaconnectorv1.GiteaConnectorSpec_builder{
			ClientId:     "client-id",
			ClientSecret: "client-secret",
			RedirectUrl:  "https://teleport.example.com/v1/webapi/gitea/callback",
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
}

func newGiteaConnectorService(t *testing.T) (*local.GiteaConnectorService, *clockwork.FakeClock) {
	t.Helper()
	clock := clockwork.NewFakeClock()
	mem, err := memory.New(memory.Config{
		Context: context.Background(),
		Clock:   clock,
	})
	require.NoError(t, err)
	t.Cleanup(func() { mem.Close() })

	service, err := local.NewGiteaConnectorService(mem)
	require.NoError(t, err)
	return service, clock
}

func TestGiteaConnectorCRUD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service, _ := newGiteaConnectorService(t)

	// Create.
	created, err := service.CreateGiteaConnector(ctx, newGiteaConnector("gitea"))
	require.NoError(t, err)
	require.NotEmpty(t, created.GetMetadata().GetRevision())
	require.Equal(t, "https://gitea.example.com/api/v1", created.GetSpec().GetApiEndpointUrl(), "validation defaults are applied on write")

	_, err = service.CreateGiteaConnector(ctx, newGiteaConnector("gitea"))
	require.Error(t, err, "duplicate create must fail")

	// Invalid connectors are rejected.
	invalid := newGiteaConnector("invalid")
	invalid.GetSpec().SetTeamsToRoles(nil)
	_, err = service.CreateGiteaConnector(ctx, invalid)
	require.Error(t, err)

	// Get strips the secret unless asked for.
	got, err := service.GetGiteaConnector(ctx, "gitea", false)
	require.NoError(t, err)
	require.Empty(t, got.GetSpec().GetClientSecret())
	require.Equal(t, "client-id", got.GetSpec().GetClientId())

	got, err = service.GetGiteaConnector(ctx, "gitea", true)
	require.NoError(t, err)
	require.Equal(t, "client-secret", got.GetSpec().GetClientSecret())

	// Update is conditional on the revision.
	got.GetSpec().SetDisplay("Gitea")
	updated, err := service.UpdateGiteaConnector(ctx, got)
	require.NoError(t, err)
	require.Equal(t, "Gitea", updated.GetSpec().GetDisplay())

	stale := newGiteaConnector("gitea")
	stale.GetMetadata().SetRevision("stale")
	_, err = service.UpdateGiteaConnector(ctx, stale)
	require.Error(t, err, "update with a stale revision must fail")

	// Upsert replaces regardless of revision.
	replacement := newGiteaConnector("gitea")
	replacement.GetSpec().SetDisplay("Replaced")
	upserted, err := service.UpsertGiteaConnector(ctx, replacement)
	require.NoError(t, err)
	require.Equal(t, "Replaced", upserted.GetSpec().GetDisplay())

	// List with and without secrets.
	for i := range 3 {
		_, err := service.CreateGiteaConnector(ctx, newGiteaConnector(fmt.Sprintf("gitea-%d", i)))
		require.NoError(t, err)
	}
	var all []*giteaconnectorv1.GiteaConnector
	token := ""
	for {
		page, next, err := service.ListGiteaConnectors(ctx, 2, token, false)
		require.NoError(t, err)
		all = append(all, page...)
		if next == "" {
			break
		}
		token = next
	}
	require.Len(t, all, 4)
	for _, c := range all {
		require.Empty(t, c.GetSpec().GetClientSecret())
	}
	withSecrets, _, err := service.ListGiteaConnectors(ctx, 0, "", true)
	require.NoError(t, err)
	require.Len(t, withSecrets, 4)
	for _, c := range withSecrets {
		require.Equal(t, "client-secret", c.GetSpec().GetClientSecret())
	}

	// Delete.
	require.NoError(t, service.DeleteGiteaConnector(ctx, "gitea"))
	_, err = service.GetGiteaConnector(ctx, "gitea", false)
	require.Error(t, err)
	require.Error(t, service.DeleteGiteaConnector(ctx, "gitea"), "deleting a missing connector must fail")

	require.NoError(t, service.DeleteAllGiteaConnectors(ctx))
	remaining, _, err := service.ListGiteaConnectors(ctx, 0, "", false)
	require.NoError(t, err)
	require.Empty(t, remaining)
}

func TestGiteaAuthRequests(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	service, clock := newGiteaConnectorService(t)

	req := giteaconnectorv1.GiteaAuthRequest_builder{
		ConnectorId:       "gitea",
		StateToken:        "state-token",
		ClientRedirectUrl: "http://127.0.0.1:1234/callback",
		CreateWebSession:  true,
		Expires:           timestamppb.New(clock.Now().Add(time.Minute)),
	}.Build()
	require.NoError(t, service.CreateGiteaAuthRequest(ctx, req))
	require.Error(t, service.CreateGiteaAuthRequest(ctx, req), "duplicate state tokens must be rejected")

	got, err := service.GetGiteaAuthRequest(ctx, "state-token")
	require.NoError(t, err)
	require.Equal(t, "gitea", got.GetConnectorId())
	require.Equal(t, "http://127.0.0.1:1234/callback", got.GetClientRedirectUrl())
	require.True(t, got.GetCreateWebSession())

	_, err = service.GetGiteaAuthRequest(ctx, "missing")
	require.Error(t, err)
	_, err = service.GetGiteaAuthRequest(ctx, "")
	require.Error(t, err)

	// Requests without the required fields are rejected.
	require.Error(t, service.CreateGiteaAuthRequest(ctx, giteaconnectorv1.GiteaAuthRequest_builder{
		ConnectorId: "gitea",
		Expires:     timestamppb.New(clock.Now().Add(time.Minute)),
	}.Build()), "missing state token")
	require.Error(t, service.CreateGiteaAuthRequest(ctx, giteaconnectorv1.GiteaAuthRequest_builder{
		ConnectorId: "gitea",
		StateToken:  "no-expiry",
	}.Build()), "missing expiry")

	// Requests expire with the backend item.
	clock.Advance(2 * time.Minute)
	_, err = service.GetGiteaAuthRequest(ctx, "state-token")
	require.Error(t, err, "expired request must not be returned")
}
