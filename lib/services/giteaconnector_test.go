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

package services

import (
	"testing"

	"github.com/stretchr/testify/require"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/api/types"
)

func validGiteaConnector() *giteaconnectorv1.GiteaConnector {
	return giteaconnectorv1.GiteaConnector_builder{
		Metadata: headerv1.Metadata_builder{Name: "gitea"}.Build(),
		Spec: giteaconnectorv1.GiteaConnectorSpec_builder{
			ClientId:     "client-id",
			ClientSecret: "client-secret",
			RedirectUrl:  "https://teleport.example.com/v1/webapi/gitea/callback",
			EndpointUrl:  "https://gitea.example.com/",
			TeamsToRoles: []*giteaconnectorv1.GiteaTeamRolesMapping{
				giteaconnectorv1.GiteaTeamRolesMapping_builder{
					Organization: "infra",
					Team:         "Owners",
					Roles:        []string{"access", "editor"},
				}.Build(),
			},
		}.Build(),
	}.Build()
}

func TestValidateGiteaConnector(t *testing.T) {
	t.Parallel()

	t.Run("defaults", func(t *testing.T) {
		c := validGiteaConnector()
		require.NoError(t, ValidateGiteaConnector(c))
		require.Equal(t, types.KindGitea, c.GetKind())
		require.Equal(t, types.V1, c.GetVersion())
		require.Equal(t, "https://gitea.example.com", c.GetSpec().GetEndpointUrl(), "trailing slash is trimmed")
		require.Equal(t, "https://gitea.example.com/api/v1", c.GetSpec().GetApiEndpointUrl(), "API endpoint defaults to endpoint + /api/v1")
	})

	t.Run("explicit api endpoint is kept", func(t *testing.T) {
		c := validGiteaConnector()
		c.GetSpec().SetApiEndpointUrl("https://api.gitea.example.com/api/v1/")
		require.NoError(t, ValidateGiteaConnector(c))
		require.Equal(t, "https://api.gitea.example.com/api/v1", c.GetSpec().GetApiEndpointUrl())
	})

	for name, mutate := range map[string]func(c *giteaconnectorv1.GiteaConnector){
		"wrong kind":       func(c *giteaconnectorv1.GiteaConnector) { c.SetKind("github") },
		"wrong version":    func(c *giteaconnectorv1.GiteaConnector) { c.SetVersion("v3") },
		"missing name":     func(c *giteaconnectorv1.GiteaConnector) { c.GetMetadata().SetName("") },
		"missing client":   func(c *giteaconnectorv1.GiteaConnector) { c.GetSpec().SetClientId("") },
		"missing redirect": func(c *giteaconnectorv1.GiteaConnector) { c.GetSpec().SetRedirectUrl("") },
		"missing endpoint": func(c *giteaconnectorv1.GiteaConnector) { c.GetSpec().SetEndpointUrl("") },
		"bad scheme":       func(c *giteaconnectorv1.GiteaConnector) { c.GetSpec().SetEndpointUrl("ftp://gitea.example.com") },
		"no host":          func(c *giteaconnectorv1.GiteaConnector) { c.GetSpec().SetEndpointUrl("https:///path") },
		"bad api endpoint": func(c *giteaconnectorv1.GiteaConnector) { c.GetSpec().SetApiEndpointUrl("not a url") },
		"no mappings":      func(c *giteaconnectorv1.GiteaConnector) { c.GetSpec().SetTeamsToRoles(nil) },
		"mapping without org": func(c *giteaconnectorv1.GiteaConnector) {
			c.GetSpec().GetTeamsToRoles()[0].SetOrganization("")
		},
		"mapping without team": func(c *giteaconnectorv1.GiteaConnector) {
			c.GetSpec().GetTeamsToRoles()[0].SetTeam("")
		},
		"mapping without roles": func(c *giteaconnectorv1.GiteaConnector) {
			c.GetSpec().GetTeamsToRoles()[0].SetRoles(nil)
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := validGiteaConnector()
			mutate(c)
			require.Error(t, ValidateGiteaConnector(c))
		})
	}
}

func TestGiteaConnectorWithoutSecrets(t *testing.T) {
	t.Parallel()

	c := validGiteaConnector()
	stripped := GiteaConnectorWithoutSecrets(c)
	require.Empty(t, stripped.GetSpec().GetClientSecret())
	require.Equal(t, "client-secret", c.GetSpec().GetClientSecret(), "original must not be modified")
	require.Equal(t, c.GetSpec().GetClientId(), stripped.GetSpec().GetClientId())
}

func TestMapGiteaClaims(t *testing.T) {
	t.Parallel()

	spec := giteaconnectorv1.GiteaConnectorSpec_builder{
		TeamsToRoles: []*giteaconnectorv1.GiteaTeamRolesMapping{
			giteaconnectorv1.GiteaTeamRolesMapping_builder{Organization: "infra", Team: "Owners", Roles: []string{"editor", "access"}}.Build(),
			giteaconnectorv1.GiteaTeamRolesMapping_builder{Organization: "infra", Team: "Developers", Roles: []string{"access"}}.Build(),
			giteaconnectorv1.GiteaTeamRolesMapping_builder{Organization: "other", Team: "Owners", Roles: []string{"auditor"}}.Build(),
		},
	}.Build()

	tests := []struct {
		name   string
		claims types.GithubClaims
		want   []string
	}{
		{
			name:   "no teams",
			claims: types.GithubClaims{},
			want:   nil,
		},
		{
			name: "single team",
			claims: types.GithubClaims{OrganizationToTeams: map[string][]string{
				"infra": {"Developers"},
			}},
			want: []string{"access"},
		},
		{
			name: "roles are deduplicated across teams",
			claims: types.GithubClaims{OrganizationToTeams: map[string][]string{
				"infra": {"Owners", "Developers"},
			}},
			want: []string{"editor", "access"},
		},
		{
			name: "team name match is scoped to the organization",
			claims: types.GithubClaims{OrganizationToTeams: map[string][]string{
				"unrelated": {"Owners"},
			}},
			want: nil,
		},
		{
			name: "team names are case sensitive",
			claims: types.GithubClaims{OrganizationToTeams: map[string][]string{
				"infra": {"owners"},
			}},
			want: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, MapGiteaClaims(spec, tt.claims))
		})
	}
}

func TestGiteaConnectorMarshalRoundTrip(t *testing.T) {
	t.Parallel()

	c := validGiteaConnector()
	require.NoError(t, ValidateGiteaConnector(c))

	data, err := MarshalGiteaConnector(c)
	require.NoError(t, err)

	out, err := UnmarshalGiteaConnector(data)
	require.NoError(t, err)
	require.Equal(t, c.GetMetadata().GetName(), out.GetMetadata().GetName())
	require.Equal(t, c.GetSpec().GetClientSecret(), out.GetSpec().GetClientSecret())
	require.Equal(t, c.GetSpec().GetApiEndpointUrl(), out.GetSpec().GetApiEndpointUrl())
	require.Len(t, out.GetSpec().GetTeamsToRoles(), 1)

	_, err = UnmarshalGiteaConnector([]byte(`{"kind":"gitea","version":"v1","metadata":{"name":"x"},"spec":{"bogus":1}}`), DisallowUnknown())
	require.Error(t, err, "unknown fields must be rejected when requested")
}
