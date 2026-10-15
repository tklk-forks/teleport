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

package tester

import (
	"context"
	"testing"

	"github.com/gravitational/trace"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/client"
)

type fakeGiteaCreator struct {
	got *giteaconnectorv1.GiteaAuthRequest
	err error
}

func (f *fakeGiteaCreator) CreateGiteaAuthRequest(_ context.Context, req *giteaconnectorv1.CreateGiteaAuthRequestRequest, _ ...grpc.CallOption) (*giteaconnectorv1.GiteaAuthRequest, error) {
	f.got = req.GetRequest()
	if f.err != nil {
		return nil, f.err
	}
	out := giteaconnectorv1.GiteaAuthRequest_builder{
		StateToken:  "state",
		RedirectUrl: "https://gitea.example.com/login/oauth/authorize?state=state",
	}.Build()
	return out, nil
}

func TestGiteaTest(t *testing.T) {
	t.Parallel()

	connector := giteaconnectorv1.GiteaConnector_builder{
		Metadata: headerv1.Metadata_builder{Name: "gitea"}.Build(),
		Spec: giteaconnectorv1.GiteaConnectorSpec_builder{
			ClientId:    "id",
			EndpointUrl: "https://gitea.example.com",
		}.Build(),
	}.Build()
	consoleReq := client.SSOLoginConsoleReq{
		ConnectorID: "-sso-test",
		RedirectURL: "http://127.0.0.1:1234/callback?secret_key=abc",
		UserPublicKeys: client.UserPublicKeys{
			SSHPubKey: []byte("ssh-ed25519 AAAA"),
		},
	}

	t.Run("success", func(t *testing.T) {
		fake := &fakeGiteaCreator{}
		info := giteaTest(fake, connector)
		resp, err := info.SSOLoginConsoleRequestFn(consoleReq)
		require.NoError(t, err)
		require.Equal(t, "https://gitea.example.com/login/oauth/authorize?state=state", resp.RedirectURL)
		require.Equal(t, "state", info.RequestID)
		require.NoError(t, info.RequestCreateErr)

		require.True(t, fake.got.GetSsoTestFlow())
		require.False(t, fake.got.GetCreateWebSession())
		require.Equal(t, "-sso-test-gitea", fake.got.GetConnectorId())
		require.Equal(t, "id", fake.got.GetConnectorSpec().GetClientId())
	})

	t.Run("error is recorded", func(t *testing.T) {
		fake := &fakeGiteaCreator{err: trace.AccessDenied("denied")}
		info := giteaTest(fake, connector)
		_, err := info.SSOLoginConsoleRequestFn(consoleReq)
		require.Error(t, err)
		require.Error(t, info.RequestCreateErr)
	})
}

func TestGetGiteaDiagInfoFields(t *testing.T) {
	t.Parallel()

	diag := &types.SSODiagnosticInfo{
		GithubClaims: &types.GithubClaims{
			Username:            "alice",
			OrganizationToTeams: map[string][]string{"infra": {"Owners"}},
		},
		GithubTeamsToRoles: []types.TeamRolesMapping{{Organization: "infra", Team: "Owners", Roles: []string{"access"}}},
		GithubTokenInfo:    &types.GithubTokenInfo{TokenType: "bearer"},
	}
	fields := getGiteaDiagInfoFields(diag, false)
	require.Len(t, fields, 3)
	require.Empty(t, fields[0], "token info is only shown with --debug")
	require.Contains(t, fields[1], "[Gitea] Received claims")
	require.Contains(t, fields[2], "[Gitea] Connector team to roles mapping")

	fields = getGiteaDiagInfoFields(diag, true)
	require.Contains(t, fields[0], "[Gitea] OAuth2 token info")
}
