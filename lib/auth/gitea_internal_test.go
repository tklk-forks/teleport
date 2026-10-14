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

package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
)

func TestPopulateGiteaClaims(t *testing.T) {
	t.Parallel()

	user := &GiteaUserResponse{Login: "alice", ID: 42, Email: "alice@example.com"}

	t.Run("teams are grouped by organization name", func(t *testing.T) {
		claims, err := populateGiteaClaims(user, []GiteaTeamResponse{
			{ID: 1, Name: "Owners", Organization: GiteaOrgResponse{Name: "infra", UserName: "infra"}},
			{ID: 2, Name: "Developers", Organization: GiteaOrgResponse{Name: "infra"}},
			// Older Gitea versions only populate the deprecated username field.
			{ID: 3, Name: "Owners", Organization: GiteaOrgResponse{UserName: "legacy"}},
			// Entries without an organization or a name are ignored.
			{ID: 4, Name: "Orphan"},
			{ID: 5, Organization: GiteaOrgResponse{Name: "infra"}},
		})
		require.NoError(t, err)
		require.Equal(t, "alice", claims.Username)
		require.Equal(t, "42", claims.UserID)
		require.Equal(t, map[string][]string{
			"infra":  {"Owners", "Developers"},
			"legacy": {"Owners"},
		}, map[string][]string(claims.OrganizationToTeams))
		require.Equal(t, []string{"Owners", "Developers", "Owners"}, claims.Teams)
	})

	t.Run("no teams is access denied", func(t *testing.T) {
		_, err := populateGiteaClaims(user, nil)
		require.Error(t, err)
	})

	t.Run("missing login is access denied", func(t *testing.T) {
		_, err := populateGiteaClaims(&GiteaUserResponse{ID: 1}, []GiteaTeamResponse{
			{Name: "Owners", Organization: GiteaOrgResponse{Name: "infra"}},
		})
		require.Error(t, err)
	})
}

// fakeGitea serves the subset of the Gitea API used during login. Teams are
// served in pages of giteaTeamsPageSize with Link headers.
type fakeGitea struct {
	t        *testing.T
	token    string
	teams    []GiteaTeamResponse
	server   *httptest.Server
	linkHost string // when set, Link headers point at this host instead
	noLinks  bool
}

func newFakeGitea(t *testing.T, teams []GiteaTeamResponse) *fakeGitea {
	f := &fakeGitea{t: t, token: "secret-token", teams: teams}
	f.server = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeGitea) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") != "token "+f.token {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"message":"token is required"}`)
		return
	}
	switch r.URL.Path {
	case "/api/v1/user":
		json.NewEncoder(w).Encode(GiteaUserResponse{Login: "alice", ID: 42, Email: "alice@example.com"})
	case "/api/v1/user/teams":
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		require.Equal(f.t, giteaTeamsPageSize, limit)
		if page < 1 {
			page = 1
		}
		start := (page - 1) * limit
		end := min(start+limit, len(f.teams))
		if start > len(f.teams) {
			start = len(f.teams)
		}
		if end < len(f.teams) && !f.noLinks {
			host := f.server.URL
			if f.linkHost != "" {
				host = f.linkHost
			}
			w.Header().Set("Link", fmt.Sprintf(`<%s/api/v1/user/teams?limit=%d&page=%d>; rel="next"`, host, limit, page+1))
		}
		json.NewEncoder(w).Encode(f.teams[start:end])
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func makeTeams(n int) []GiteaTeamResponse {
	teams := make([]GiteaTeamResponse, 0, n)
	for i := range n {
		teams = append(teams, GiteaTeamResponse{
			ID:           int64(i),
			Name:         fmt.Sprintf("team-%d", i),
			Organization: GiteaOrgResponse{Name: "infra"},
		})
	}
	return teams
}

func TestGiteaAPIClient(t *testing.T) {
	t.Parallel()
	ctx := t.Context()

	t.Run("user", func(t *testing.T) {
		f := newFakeGitea(t, nil)
		c, err := newGiteaAPIClient(f.server.URL+"/api/v1", f.token, f.server.Client())
		require.NoError(t, err)
		user, err := c.getUser(ctx)
		require.NoError(t, err)
		require.Equal(t, &GiteaUserResponse{Login: "alice", ID: 42, Email: "alice@example.com"}, user)
	})

	t.Run("bad token", func(t *testing.T) {
		f := newFakeGitea(t, nil)
		c, err := newGiteaAPIClient(f.server.URL+"/api/v1/", "wrong", f.server.Client())
		require.NoError(t, err)
		_, err = c.getUser(ctx)
		require.Error(t, err)
	})

	t.Run("teams follow link headers", func(t *testing.T) {
		f := newFakeGitea(t, makeTeams(2*giteaTeamsPageSize+3))
		c, err := newGiteaAPIClient(f.server.URL+"/api/v1", f.token, f.server.Client())
		require.NoError(t, err)
		teams, err := c.getTeams(ctx)
		require.NoError(t, err)
		require.Len(t, teams, 2*giteaTeamsPageSize+3)
		require.Equal(t, "team-0", teams[0].Name)
		require.Equal(t, fmt.Sprintf("team-%d", 2*giteaTeamsPageSize+2), teams[len(teams)-1].Name)
	})

	t.Run("teams paginate without link headers", func(t *testing.T) {
		f := newFakeGitea(t, makeTeams(giteaTeamsPageSize+1))
		f.noLinks = true
		c, err := newGiteaAPIClient(f.server.URL+"/api/v1", f.token, f.server.Client())
		require.NoError(t, err)
		teams, err := c.getTeams(ctx)
		require.NoError(t, err)
		require.Len(t, teams, giteaTeamsPageSize+1)
	})

	t.Run("exact page boundary without link headers", func(t *testing.T) {
		f := newFakeGitea(t, makeTeams(giteaTeamsPageSize))
		f.noLinks = true
		c, err := newGiteaAPIClient(f.server.URL+"/api/v1", f.token, f.server.Client())
		require.NoError(t, err)
		teams, err := c.getTeams(ctx)
		require.NoError(t, err)
		require.Len(t, teams, giteaTeamsPageSize)
	})

	t.Run("link headers pointing elsewhere are rejected", func(t *testing.T) {
		f := newFakeGitea(t, makeTeams(giteaTeamsPageSize+1))
		f.linkHost = "https://attacker.example.com"
		c, err := newGiteaAPIClient(f.server.URL+"/api/v1", f.token, f.server.Client())
		require.NoError(t, err)
		_, err = c.getTeams(ctx)
		require.Error(t, err)
	})

	t.Run("invalid endpoint", func(t *testing.T) {
		_, err := newGiteaAPIClient("gitea.example.com/api/v1", "t", http.DefaultClient)
		require.Error(t, err)
	})
}

func TestNewGiteaOAuth2Config(t *testing.T) {
	t.Parallel()
	spec := giteaconnectorv1.GiteaConnectorSpec_builder{
		ClientId:     "id",
		ClientSecret: "secret",
		RedirectUrl:  "https://proxy.example.com/v1/webapi/gitea/callback",
		EndpointUrl:  "https://gitea.example.com",
	}.Build()
	cfg := newGiteaOAuth2Config(spec)
	require.Equal(t, "https://gitea.example.com/login/oauth/authorize", cfg.Endpoint.AuthURL)
	require.Equal(t, "https://gitea.example.com/login/oauth/access_token", cfg.Endpoint.TokenURL)
	require.Equal(t, []string{"read:user", "read:organization"}, cfg.Scopes)
	url := cfg.AuthCodeURL("state-123")
	require.Contains(t, url, "state=state-123")
	require.Contains(t, url, "scope=read%3Auser+read%3Aorganization")
	require.Contains(t, url, "client_id=id")
}
