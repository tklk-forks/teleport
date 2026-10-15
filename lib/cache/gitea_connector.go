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

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/proto"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils/clientutils"
	"github.com/gravitational/teleport/lib/itertools/stream"
	"github.com/gravitational/teleport/lib/services"
)

type giteaConnectorIndex string

const giteaConnectorNameIndex giteaConnectorIndex = "name"

func newGiteaConnectorCollection(upstream services.GiteaConnectorsGetter, w types.WatchKind) (*collection[*giteaconnectorv1.GiteaConnector, giteaConnectorIndex], error) {
	if upstream == nil {
		return nil, trace.BadParameter("missing parameter GiteaConnectors")
	}

	return &collection[*giteaconnectorv1.GiteaConnector, giteaConnectorIndex]{
		store: newStore(
			types.KindGitea,
			proto.CloneOf[*giteaconnectorv1.GiteaConnector],
			map[giteaConnectorIndex]func(*giteaconnectorv1.GiteaConnector) string{
				giteaConnectorNameIndex: func(r *giteaconnectorv1.GiteaConnector) string {
					return r.GetMetadata().GetName()
				},
			}),
		fetcher: func(ctx context.Context, loadSecrets bool) ([]*giteaconnectorv1.GiteaConnector, error) {
			out, err := stream.Collect(clientutils.Resources(ctx, func(ctx context.Context, pageSize int, pageToken string) ([]*giteaconnectorv1.GiteaConnector, string, error) {
				return upstream.ListGiteaConnectors(ctx, pageSize, pageToken, loadSecrets)
			}))
			return out, trace.Wrap(err)
		},
		headerTransform: func(hdr *types.ResourceHeader) *giteaconnectorv1.GiteaConnector {
			return giteaconnectorv1.GiteaConnector_builder{
				Kind:    hdr.Kind,
				Version: hdr.Version,
				Metadata: headerv1.Metadata_builder{
					Name: hdr.Metadata.Name,
				}.Build(),
			}.Build()
		},
		watch: w,
	}, nil
}

// giteaConnectorFromCache returns a copy of a cached connector, with the
// client secret removed unless requested.
func giteaConnectorFromCache(c *giteaconnectorv1.GiteaConnector, withSecrets bool) *giteaconnectorv1.GiteaConnector {
	if withSecrets {
		return proto.CloneOf(c)
	}
	return services.GiteaConnectorWithoutSecrets(c)
}

// GetGiteaConnector returns a Gitea connector by name.
func (c *Cache) GetGiteaConnector(ctx context.Context, name string, withSecrets bool) (*giteaconnectorv1.GiteaConnector, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/GetGiteaConnector")
	defer span.End()

	rg, err := acquireReadGuard(c, c.collections.giteaConnectors)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	defer rg.Release()

	// A cache that was not asked to load secrets cannot serve them.
	if !rg.ReadCache() || (withSecrets && !c.collections.giteaConnectors.watch.LoadSecrets) {
		connector, err := c.Config.GiteaConnectors.GetGiteaConnector(ctx, name, withSecrets)
		return connector, trace.Wrap(err)
	}

	connector, err := rg.store.get(giteaConnectorNameIndex, name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return giteaConnectorFromCache(connector, withSecrets), nil
}

// ListGiteaConnectors returns a page of Gitea connectors.
func (c *Cache) ListGiteaConnectors(ctx context.Context, pageSize int, pageToken string, withSecrets bool) ([]*giteaconnectorv1.GiteaConnector, string, error) {
	ctx, span := c.Tracer.Start(ctx, "cache/ListGiteaConnectors")
	defer span.End()

	rg, err := acquireReadGuard(c, c.collections.giteaConnectors)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	defer rg.Release()

	if !rg.ReadCache() || (withSecrets && !c.collections.giteaConnectors.watch.LoadSecrets) {
		out, next, err := c.Config.GiteaConnectors.ListGiteaConnectors(ctx, pageSize, pageToken, withSecrets)
		return out, next, trace.Wrap(err)
	}

	if pageSize <= 0 || pageSize > apidefaults.DefaultChunkSize {
		pageSize = apidefaults.DefaultChunkSize
	}
	var out []*giteaconnectorv1.GiteaConnector
	for item := range rg.store.resources(giteaConnectorNameIndex, pageToken, "") {
		if len(out) == pageSize {
			return out, item.GetMetadata().GetName(), nil
		}
		out = append(out, giteaConnectorFromCache(item, withSecrets))
	}
	return out, "", nil
}
