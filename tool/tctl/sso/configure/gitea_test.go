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

package configure

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

func TestNewGiteaConnectorFromFlags(t *testing.T) {
	t.Parallel()

	flags := &giteaFlags{
		connectorName: "gitea",
		clientID:      "id",
		clientSecret:  "secret",
		redirectURL:   "https://proxy.example.com/v1/webapi/gitea/callback",
		endpointURL:   "https://gitea.example.com/",
		display:       "Gitea",
		teamsToRoles: []types.TeamRolesMapping{
			{Organization: "infra", Team: "Owners", Roles: []string{"access", "editor"}},
		},
	}
	connector, err := newGiteaConnectorFromFlags(flags)
	require.NoError(t, err)
	require.Equal(t, "https://gitea.example.com/api/v1", services.GiteaAPIEndpointURL(connector.GetSpec()))

	// The YAML printed by the command must be accepted by "tctl create" and
	// "tctl sso test", which both parse it with UnmarshalGiteaConnector.
	var buf bytes.Buffer
	require.NoError(t, utils.WriteYAML(&buf, types.ProtoResource153ToLegacy(connector)))
	require.Contains(t, buf.String(), "kind: gitea")
	require.Contains(t, buf.String(), "teams_to_roles:")

	raw, err := utils.ToJSON(buf.Bytes())
	require.NoError(t, err)
	parsed, err := services.UnmarshalGiteaConnector(raw, services.DisallowUnknown())
	require.NoError(t, err)
	require.Equal(t, "secret", parsed.GetSpec().GetClientSecret())
	require.Equal(t, "Owners", parsed.GetSpec().GetTeamsToRoles()[0].GetTeam())

	// Invalid input is rejected before anything is printed.
	flags.endpointURL = "gitea.example.com"
	_, err = newGiteaConnectorFromFlags(flags)
	require.Error(t, err)
}
