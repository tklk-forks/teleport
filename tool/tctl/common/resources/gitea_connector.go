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

package resources

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/gravitational/trace"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/asciitable"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/services"
)

type giteaConnectorCollection struct {
	connectors []*giteaconnectorv1.GiteaConnector
}

func (c *giteaConnectorCollection) Resources() []types.Resource {
	r := make([]types.Resource, 0, len(c.connectors))
	for _, connector := range c.connectors {
		r = append(r, types.ProtoResource153ToLegacy(connector))
	}
	return r
}

func (c *giteaConnectorCollection) WriteText(w io.Writer, verbose bool) error {
	t := asciitable.MakeTable([]string{"Name", "Endpoint URL", "Teams To Roles"})
	for _, conn := range c.connectors {
		t.AddRow([]string{
			conn.GetMetadata().GetName(),
			conn.GetSpec().GetEndpointUrl(),
			formatGiteaTeamsToRoles(conn.GetSpec().GetTeamsToRoles()),
		})
	}
	_, err := t.AsBuffer().WriteTo(w)
	return trace.Wrap(err)
}

func formatGiteaTeamsToRoles(mappings []*giteaconnectorv1.GiteaTeamRolesMapping) string {
	result := make([]string, 0, len(mappings))
	for _, m := range mappings {
		result = append(result, fmt.Sprintf("@%v/%v: %v",
			m.GetOrganization(), m.GetTeam(), strings.Join(m.GetRoles(), ", ")))
	}
	return strings.Join(result, ", ")
}

func giteaConnectorHandler() Handler {
	return Handler{
		getHandler:    getGiteaConnector,
		createHandler: createGiteaConnector,
		updateHandler: updateGiteaConnector,
		deleteHandler: deleteGiteaConnector,
		singleton:     false,
		mfaRequired:   true,
		description:   "Configures how users can connect using Gitea.",
	}
}

type giteaConnectorGetter struct {
	client giteaconnectorv1.GiteaConnectorServiceClient
}

func (g giteaConnectorGetter) GetGiteaConnector(ctx context.Context, name string, withSecrets bool) (*giteaconnectorv1.GiteaConnector, error) {
	connector, err := g.client.GetGiteaConnector(ctx, giteaconnectorv1.GetGiteaConnectorRequest_builder{
		Name:        name,
		WithSecrets: withSecrets,
	}.Build())
	return connector, trace.Wrap(err)
}

func (g giteaConnectorGetter) ListGiteaConnectors(ctx context.Context, pageSize int, pageToken string, withSecrets bool) ([]*giteaconnectorv1.GiteaConnector, string, error) {
	resp, err := g.client.ListGiteaConnectors(ctx, giteaconnectorv1.ListGiteaConnectorsRequest_builder{
		PageSize:    int32(pageSize),
		PageToken:   pageToken,
		WithSecrets: withSecrets,
	}.Build())
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	return resp.GetConnectors(), resp.GetNextPageToken(), nil
}

func getGiteaConnector(ctx context.Context, client *authclient.Client, ref services.Ref, opts GetOpts) (Collection, error) {
	getter := giteaConnectorGetter{client: client.GiteaConnectorClient()}
	if ref.Name == "" {
		connectors, err := services.GetAllGiteaConnectors(ctx, getter, opts.WithSecrets)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return &giteaConnectorCollection{connectors: connectors}, nil
	}
	connector, err := getter.GetGiteaConnector(ctx, ref.Name, opts.WithSecrets)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &giteaConnectorCollection{connectors: []*giteaconnectorv1.GiteaConnector{connector}}, nil
}

func createGiteaConnector(ctx context.Context, client *authclient.Client, raw services.UnknownResource, opts CreateOpts) error {
	connector, err := services.UnmarshalGiteaConnector(raw.Raw, services.DisallowUnknown())
	if err != nil {
		return trace.Wrap(err)
	}
	if err := services.ValidateGiteaConnector(connector); err != nil {
		return trace.Wrap(err)
	}
	clt := client.GiteaConnectorClient()
	if opts.Force {
		upserted, err := clt.UpsertGiteaConnector(ctx, giteaconnectorv1.UpsertGiteaConnectorRequest_builder{Connector: connector}.Build())
		if err != nil {
			return trace.Wrap(err)
		}
		fmt.Printf("authentication connector %q has been updated\n", upserted.GetMetadata().GetName())
		return nil
	}
	created, err := clt.CreateGiteaConnector(ctx, giteaconnectorv1.CreateGiteaConnectorRequest_builder{Connector: connector}.Build())
	if err != nil {
		if trace.IsAlreadyExists(err) {
			return trace.AlreadyExists("authentication connector %q already exists", connector.GetMetadata().GetName())
		}
		return trace.Wrap(err)
	}
	fmt.Printf("authentication connector %q has been created\n", created.GetMetadata().GetName())
	return nil
}

func updateGiteaConnector(ctx context.Context, client *authclient.Client, raw services.UnknownResource, opts CreateOpts) error {
	connector, err := services.UnmarshalGiteaConnector(raw.Raw, services.DisallowUnknown())
	if err != nil {
		return trace.Wrap(err)
	}
	if err := services.ValidateGiteaConnector(connector); err != nil {
		return trace.Wrap(err)
	}
	updated, err := client.GiteaConnectorClient().UpdateGiteaConnector(ctx, giteaconnectorv1.UpdateGiteaConnectorRequest_builder{Connector: connector}.Build())
	if err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("authentication connector %q has been updated\n", updated.GetMetadata().GetName())
	return nil
}

func deleteGiteaConnector(ctx context.Context, client *authclient.Client, ref services.Ref) error {
	if _, err := client.GiteaConnectorClient().DeleteGiteaConnector(ctx, giteaconnectorv1.DeleteGiteaConnectorRequest_builder{Name: ref.Name}.Build()); err != nil {
		return trace.Wrap(err)
	}
	fmt.Printf("authentication connector %q has been deleted\n", ref.Name)
	return nil
}
