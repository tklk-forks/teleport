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
	"context"
	"io"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/gravitational/trace"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

// giteaFlags holds the values parsed for "tctl sso configure gitea".
type giteaFlags struct {
	connectorName      string
	clientID           string
	clientSecret       string
	redirectURL        string
	endpointURL        string
	apiEndpointURL     string
	display            string
	teamsToRoles       []types.TeamRolesMapping
	ignoreMissingRoles bool
}

func addGiteaCommand(cmd *SSOConfigureCommand) *AuthKindCommand {
	flags := &giteaFlags{}

	sub := cmd.ConfigureCmd.Command("gitea", "Configure Gitea auth connector.")
	// commonly used flags
	sub.Flag("name", "Connector name.").Default("gitea").Short('n').StringVar(&flags.connectorName)
	sub.Flag("teams-to-roles", "Sets teams-to-roles mapping using format 'organization,team,role1,role2,...'. Gitea team names are matched exactly. Repeatable.").
		Short('r').
		Required().
		PlaceHolder("org,team,role1,role2,...").
		SetValue(newTeamsToRolesParser(&flags.teamsToRoles))
	sub.Flag("display", "Sets the connector display name.").StringVar(&flags.display)
	sub.Flag("id", "Gitea OAuth2 application client ID.").PlaceHolder("ID").Required().StringVar(&flags.clientID)
	sub.Flag("secret", "Gitea OAuth2 application client secret.").Required().PlaceHolder("SECRET").StringVar(&flags.clientSecret)
	sub.Flag("endpoint-url", "Base URL of the Gitea instance, e.g. https://gitea.example.com.").
		PlaceHolder("URL").
		Required().
		StringVar(&flags.endpointURL)
	sub.Flag("api-endpoint-url", "Gitea REST API URL. Defaults to the endpoint URL followed by /api/v1.").
		PlaceHolder("URL").
		StringVar(&flags.apiEndpointURL)

	// auto
	sub.Flag("redirect-url", "Authorization callback URL.").PlaceHolder("URL").StringVar(&flags.redirectURL)

	// ignores
	sub.Flag("ignore-missing-roles", "Ignore missing roles referenced in --teams-to-roles.").BoolVar(&flags.ignoreMissingRoles)

	sub.Alias(`
Examples:

  > tctl sso configure gitea --endpoint-url https://gitea.example.com -r infra,Owners,access,editor -r infra,Developers,access --id CLIENT_ID --secret CLIENT_SECRET

  Generate Gitea auth connector. Two role mappings are defined:
    - members of the 'Owners' team in the 'infra' org will receive 'access' and 'editor' roles.
    - members of the 'Developers' team in the 'infra' org will receive the 'access' role.

  The values for --id and --secret are provided by the OAuth2 application registered in Gitea.

  > tctl sso configure gitea ... | tctl sso test

  Generate the configuration and immediately test it using "tctl sso test" command.`)

	preset := &AuthKindCommand{
		Run: func(ctx context.Context, clt *authclient.Client) error {
			return giteaRunFunc(ctx, cmd, flags, clt, os.Stdout)
		},
	}

	sub.Action(func(ctx *kingpin.ParseContext) error {
		preset.Parsed = true
		return nil
	})

	return preset
}

func giteaRunFunc(ctx context.Context, cmd *SSOConfigureCommand, flags *giteaFlags, clt *authclient.Client, out io.Writer) error {
	if err := specCheckRoles(ctx, cmd.Logger, flags.teamsToRoles, flags.ignoreMissingRoles, clt); err != nil {
		return trace.Wrap(err)
	}

	if flags.redirectURL == "" {
		flags.redirectURL = ResolveCallbackURL(ctx, cmd.Logger, clt, "RedirectURL", "https://%v/v1/webapi/gitea/callback")
	}

	connector, err := newGiteaConnectorFromFlags(flags)
	if err != nil {
		return trace.Wrap(err)
	}
	return trace.Wrap(utils.WriteYAML(out, types.ProtoResource153ToLegacy(connector)))
}

// newGiteaConnectorFromFlags builds and validates a connector from flags.
func newGiteaConnectorFromFlags(flags *giteaFlags) (*giteaconnectorv1.GiteaConnector, error) {
	mappings := make([]*giteaconnectorv1.GiteaTeamRolesMapping, 0, len(flags.teamsToRoles))
	for _, m := range flags.teamsToRoles {
		mappings = append(mappings, giteaconnectorv1.GiteaTeamRolesMapping_builder{
			Organization: m.Organization,
			Team:         m.Team,
			Roles:        m.Roles,
		}.Build())
	}
	connector := giteaconnectorv1.GiteaConnector_builder{
		Kind:     types.KindGitea,
		Version:  types.V1,
		Metadata: headerv1.Metadata_builder{Name: flags.connectorName}.Build(),
		Spec: giteaconnectorv1.GiteaConnectorSpec_builder{
			ClientId:       flags.clientID,
			ClientSecret:   flags.clientSecret,
			RedirectUrl:    flags.redirectURL,
			EndpointUrl:    flags.endpointURL,
			ApiEndpointUrl: flags.apiEndpointURL,
			Display:        flags.display,
			TeamsToRoles:   mappings,
		}.Build(),
	}.Build()
	if err := services.ValidateGiteaConnector(connector); err != nil {
		return nil, trace.Wrap(err)
	}
	return connector, nil
}
