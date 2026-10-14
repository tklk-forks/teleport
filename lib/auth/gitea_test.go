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

package auth_test

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authtest"
)

func TestGiteaCallbackFlow(t *testing.T) {
	srv := newTestTLSServer(t)
	ctx := t.Context()
	a := srv.Auth()

	connector := giteaconnectorv1.GiteaConnector_builder{
		Metadata: headerv1.Metadata_builder{Name: "gitea"}.Build(),
		Spec: giteaconnectorv1.GiteaConnectorSpec_builder{
			ClientId:     "test-client-id",
			ClientSecret: "test-client-secret",
			RedirectUrl:  "https://example.com/v1/webapi/gitea/callback",
			EndpointUrl:  "https://gitea.example.com",
			Display:      "Sign in with Gitea",
			TeamsToRoles: []*giteaconnectorv1.GiteaTeamRolesMapping{
				giteaconnectorv1.GiteaTeamRolesMapping_builder{
					Organization: "infra",
					Team:         "Owners",
					Roles:        []string{"access"},
				}.Build(),
			},
		}.Build(),
	}.Build()
	_, err := a.CreateGiteaConnector(ctx, connector)
	require.NoError(t, err)

	_, err = authtest.CreateRole(ctx, a, "access", types.RoleSpecV6{})
	require.NoError(t, err)

	proxyClient, err := srv.NewClient(authtest.TestBuiltin(types.RoleProxy))
	require.NoError(t, err)
	giteaClient := proxyClient.GiteaConnectorClient()

	// The proxy may read connectors but never their secrets.
	got, err := giteaClient.GetGiteaConnector(ctx, giteaconnectorv1.GetGiteaConnectorRequest_builder{Name: "gitea"}.Build())
	require.NoError(t, err)
	require.Empty(t, got.GetSpec().GetClientSecret())
	_, err = giteaClient.GetGiteaConnector(ctx, giteaconnectorv1.GetGiteaConnectorRequest_builder{Name: "gitea", WithSecrets: true}.Build())
	require.Error(t, err)

	createRequest := func(t *testing.T, webSession bool) *giteaconnectorv1.GiteaAuthRequest {
		t.Helper()
		req, err := giteaClient.CreateGiteaAuthRequest(ctx, giteaconnectorv1.CreateGiteaAuthRequestRequest_builder{
			Request: giteaconnectorv1.GiteaAuthRequest_builder{
				ConnectorId:      "gitea",
				CertTtl:          durationpb.New(apidefaults.MinCertDuration),
				CreateWebSession: webSession,
				// tsh-style logins must carry an allowed client redirect URL.
				ClientRedirectUrl: "http://127.0.0.1:1234/callback?secret_key=abc",
			}.Build(),
		}.Build())
		require.NoError(t, err)
		require.NotEmpty(t, req.GetStateToken())
		require.Contains(t, req.GetRedirectUrl(), "https://gitea.example.com/login/oauth/authorize?")
		require.Contains(t, req.GetRedirectUrl(), "state="+req.GetStateToken())
		return req
	}

	t.Run("unknown connector", func(t *testing.T) {
		_, err := giteaClient.CreateGiteaAuthRequest(ctx, giteaconnectorv1.CreateGiteaAuthRequestRequest_builder{
			Request: giteaconnectorv1.GiteaAuthRequest_builder{ConnectorId: "missing", CreateWebSession: true}.Build(),
		}.Build())
		require.Error(t, err)
	})

	t.Run("disallowed client redirect", func(t *testing.T) {
		_, err := giteaClient.CreateGiteaAuthRequest(ctx, giteaconnectorv1.CreateGiteaAuthRequestRequest_builder{
			Request: giteaconnectorv1.GiteaAuthRequest_builder{
				ConnectorId:       "gitea",
				ClientRedirectUrl: "https://attacker.example.com/callback",
			}.Build(),
		}.Build())
		require.Error(t, err)
	})

	t.Run("user with no mapped team", func(t *testing.T) {
		a.GiteaUserAndTeamsOverride = func() (*auth.GiteaUserResponse, []auth.GiteaTeamResponse, error) {
			return &auth.GiteaUserResponse{Login: "bob", ID: 7}, []auth.GiteaTeamResponse{{
				Name:         "Guests",
				Organization: auth.GiteaOrgResponse{Name: "infra"},
			}}, nil
		}
		req := createRequest(t, true)
		resp, err := proxyClient.ValidateGiteaAuthCallback(ctx, url.Values{
			"code":  []string{"test-code"},
			"state": []string{req.GetStateToken()},
		})
		require.Nil(t, resp)
		require.ErrorIs(t, err, auth.ErrGiteaNoRoles)
	})

	t.Run("web session for mapped user", func(t *testing.T) {
		a.GiteaUserAndTeamsOverride = func() (*auth.GiteaUserResponse, []auth.GiteaTeamResponse, error) {
			return &auth.GiteaUserResponse{Login: "alice", ID: 42, Email: "alice@example.com"}, []auth.GiteaTeamResponse{{
				Name:         "Owners",
				Organization: auth.GiteaOrgResponse{Name: "infra"},
			}}, nil
		}
		req := createRequest(t, true)
		resp, err := proxyClient.ValidateGiteaAuthCallback(ctx, url.Values{
			"code":  []string{"test-code"},
			"state": []string{req.GetStateToken()},
		})
		require.NoError(t, err)
		require.Equal(t, "alice", resp.Username)
		require.True(t, resp.Req.CreateWebSession)
		require.NotNil(t, resp.Session)
		require.Equal(t, "gitea", resp.Identity.ConnectorID)
		require.Equal(t, "42", resp.Identity.UserID)

		user, err := a.GetUser(ctx, "alice", false)
		require.NoError(t, err)
		require.Equal(t, []string{"access"}, user.GetRoles())
		require.Equal(t, constants.Gitea, user.GetCreatedBy().Connector.Type)
		require.Equal(t, []string{"Owners"}, user.GetTraits()["gitea_teams"])
		require.Equal(t, []string{"alice@example.com"}, user.GetTraits()["email"])
	})

	t.Run("console login issues certificates", func(t *testing.T) {
		a.GiteaUserAndTeamsOverride = func() (*auth.GiteaUserResponse, []auth.GiteaTeamResponse, error) {
			return &auth.GiteaUserResponse{Login: "alice", ID: 42}, []auth.GiteaTeamResponse{{
				Name:         "Owners",
				Organization: auth.GiteaOrgResponse{Name: "infra"},
			}}, nil
		}
		_, sshPub, _, tlsPub := newSSHAndTLSKeyPairs(t)
		req, err := giteaClient.CreateGiteaAuthRequest(ctx, giteaconnectorv1.CreateGiteaAuthRequestRequest_builder{
			Request: giteaconnectorv1.GiteaAuthRequest_builder{
				ConnectorId:       "gitea",
				CertTtl:           durationpb.New(apidefaults.MinCertDuration),
				SshPublicKey:      sshPub,
				TlsPublicKey:      tlsPub,
				ClientRedirectUrl: "http://127.0.0.1:1234/callback?secret_key=abc",
			}.Build(),
		}.Build())
		require.NoError(t, err)

		resp, err := proxyClient.ValidateGiteaAuthCallback(ctx, url.Values{
			"code":  []string{"test-code"},
			"state": []string{req.GetStateToken()},
		})
		require.NoError(t, err)
		require.False(t, resp.Req.CreateWebSession)
		require.Nil(t, resp.Session)
		require.NotEmpty(t, resp.Cert)
		require.NotEmpty(t, resp.TLSCert)
		require.Len(t, resp.HostSigners, 1)
		require.Equal(t, "http://127.0.0.1:1234/callback?secret_key=abc", resp.Req.ClientRedirectURL)
	})

	t.Run("callback error from provider", func(t *testing.T) {
		req := createRequest(t, true)
		_, err := proxyClient.ValidateGiteaAuthCallback(ctx, url.Values{
			"error":             []string{"access_denied"},
			"error_description": []string{"user cancelled"},
			"state":             []string{req.GetStateToken()},
		})
		require.Error(t, err)
	})

	t.Run("missing state", func(t *testing.T) {
		_, err := proxyClient.ValidateGiteaAuthCallback(ctx, url.Values{"code": []string{"x"}})
		require.Error(t, err)
	})
}
