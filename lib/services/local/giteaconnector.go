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

package local

import (
	"context"
	"strings"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/encoding/protojson"

	apidefaults "github.com/gravitational/teleport/api/defaults"
	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/backend"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/services/local/generic"
)

const giteaPrefix = "gitea"

// GiteaConnectorService persists Gitea connectors and their pending auth
// requests in the backend.
type GiteaConnectorService struct {
	backend backend.Backend
	service *generic.ServiceWrapper[*giteaconnectorv1.GiteaConnector]
}

// NewGiteaConnectorService returns a new Gitea connector storage service.
func NewGiteaConnectorService(b backend.Backend) (*GiteaConnectorService, error) {
	service, err := generic.NewServiceWrapper(
		generic.ServiceConfig[*giteaconnectorv1.GiteaConnector]{
			Backend:       b,
			ResourceKind:  types.KindGitea,
			BackendPrefix: giteaConnectorsKey(),
			MarshalFunc:   services.MarshalGiteaConnector,
			UnmarshalFunc: services.UnmarshalGiteaConnector,
			ValidateFunc:  services.ValidateGiteaConnector,
		})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &GiteaConnectorService{backend: b, service: service}, nil
}

// GetGiteaConnector returns a Gitea connector by name.
func (s *GiteaConnectorService) GetGiteaConnector(ctx context.Context, name string, withSecrets bool) (*giteaconnectorv1.GiteaConnector, error) {
	connector, err := s.service.GetResource(ctx, name)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if !withSecrets {
		connector = services.GiteaConnectorWithoutSecrets(connector)
	}
	return connector, nil
}

// ListGiteaConnectors returns a page of Gitea connectors.
func (s *GiteaConnectorService) ListGiteaConnectors(ctx context.Context, pageSize int, pageToken string, withSecrets bool) ([]*giteaconnectorv1.GiteaConnector, string, error) {
	connectors, next, err := s.service.ListResources(ctx, pageSize, pageToken)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	if !withSecrets {
		for i, c := range connectors {
			connectors[i] = services.GiteaConnectorWithoutSecrets(c)
		}
	}
	return connectors, next, nil
}

// CreateGiteaConnector creates a new Gitea connector.
func (s *GiteaConnectorService) CreateGiteaConnector(ctx context.Context, connector *giteaconnectorv1.GiteaConnector) (*giteaconnectorv1.GiteaConnector, error) {
	created, err := s.service.CreateResource(ctx, connector)
	return created, trace.Wrap(err)
}

// UpdateGiteaConnector updates an existing Gitea connector.
func (s *GiteaConnectorService) UpdateGiteaConnector(ctx context.Context, connector *giteaconnectorv1.GiteaConnector) (*giteaconnectorv1.GiteaConnector, error) {
	updated, err := s.service.ConditionalUpdateResource(ctx, connector)
	return updated, trace.Wrap(err)
}

// UpsertGiteaConnector creates or replaces a Gitea connector.
func (s *GiteaConnectorService) UpsertGiteaConnector(ctx context.Context, connector *giteaconnectorv1.GiteaConnector) (*giteaconnectorv1.GiteaConnector, error) {
	upserted, err := s.service.UpsertResource(ctx, connector)
	return upserted, trace.Wrap(err)
}

// DeleteGiteaConnector deletes a Gitea connector by name.
func (s *GiteaConnectorService) DeleteGiteaConnector(ctx context.Context, name string) error {
	return trace.Wrap(s.service.DeleteResource(ctx, name))
}

// DeleteAllGiteaConnectors deletes all Gitea connectors.
func (s *GiteaConnectorService) DeleteAllGiteaConnectors(ctx context.Context) error {
	return trace.Wrap(s.service.DeleteAllResources(ctx))
}

func giteaAuthRequestKey(stateToken string) backend.Key {
	return backend.NewKey(webPrefix, connectorsPrefix, giteaPrefix, requestsPrefix, stateToken)
}

// CreateGiteaAuthRequest stores a pending Gitea auth request. The item expires
// together with the request.
func (s *GiteaConnectorService) CreateGiteaAuthRequest(ctx context.Context, req *giteaconnectorv1.GiteaAuthRequest) error {
	if req.GetStateToken() == "" {
		return trace.BadParameter("missing parameter state_token")
	}
	if req.GetConnectorId() == "" {
		return trace.BadParameter("missing parameter connector_id")
	}
	if !req.HasExpires() {
		return trace.BadParameter("missing parameter expires")
	}
	value, err := protojson.Marshal(req)
	if err != nil {
		return trace.Wrap(err)
	}
	item := backend.Item{
		Key:     giteaAuthRequestKey(req.GetStateToken()),
		Value:   value,
		Expires: req.GetExpires().AsTime(),
	}
	if _, err := s.backend.Create(ctx, item); err != nil {
		return trace.Wrap(err)
	}
	return nil
}

// GetGiteaAuthRequest returns a pending Gitea auth request by state token.
func (s *GiteaConnectorService) GetGiteaAuthRequest(ctx context.Context, stateToken string) (*giteaconnectorv1.GiteaAuthRequest, error) {
	if stateToken == "" {
		return nil, trace.BadParameter("missing parameter state_token")
	}
	item, err := s.backend.Get(ctx, giteaAuthRequestKey(stateToken))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req := &giteaconnectorv1.GiteaAuthRequest{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(item.Value, req); err != nil {
		return nil, trace.Wrap(err)
	}
	return req, nil
}

func giteaConnectorsKey() backend.Key {
	return backend.NewKey(webPrefix, connectorsPrefix, giteaPrefix, connectorsPrefix)
}

func newGiteaConnectorParser(loadSecrets bool) *giteaConnectorParser {
	return &giteaConnectorParser{
		baseParser:  newBaseParser(giteaConnectorsKey()),
		loadSecrets: loadSecrets,
	}
}

// giteaConnectorParser converts backend events for Gitea connectors into
// resources. Client secrets are stripped unless the watcher asked for them.
type giteaConnectorParser struct {
	baseParser
	loadSecrets bool
}

func (p *giteaConnectorParser) parse(event backend.Event) (types.Resource, error) {
	switch event.Type {
	case types.OpDelete:
		name := strings.TrimPrefix(event.Item.Key.TrimPrefix(giteaConnectorsKey()).String(), backend.SeparatorString)
		if name == "" {
			return nil, trace.NotFound("failed parsing %v", event.Item.Key.String())
		}
		return &types.ResourceHeader{
			Kind:    types.KindGitea,
			Version: types.V1,
			Metadata: types.Metadata{
				Name:      name,
				Namespace: apidefaults.Namespace,
			},
		}, nil
	case types.OpPut:
		connector, err := services.UnmarshalGiteaConnector(event.Item.Value,
			services.WithExpires(event.Item.Expires),
			services.WithRevision(event.Item.Revision),
		)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		if !p.loadSecrets {
			connector = services.GiteaConnectorWithoutSecrets(connector)
		}
		return types.ProtoResource153ToLegacy(connector), nil
	default:
		return nil, trace.BadParameter("event %v is not supported", event.Type)
	}
}
