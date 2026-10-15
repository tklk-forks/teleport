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

// Package giteav1 implements the gRPC service that manages Gitea auth
// connectors and starts Gitea OAuth2 login flows.
package giteav1

import (
	"context"
	"log/slog"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/types/known/emptypb"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/services"
)

// AuthServer is the subset of the auth server used to drive login flows.
type AuthServer interface {
	// CreateGiteaAuthRequest starts a Gitea login flow.
	CreateGiteaAuthRequest(ctx context.Context, req *giteaconnectorv1.GiteaAuthRequest) (*giteaconnectorv1.GiteaAuthRequest, error)
	// GetGiteaAuthRequest returns a pending auth request by state token.
	GetGiteaAuthRequest(ctx context.Context, stateToken string) (*giteaconnectorv1.GiteaAuthRequest, error)
}

// ServiceConfig holds the dependencies of the Gitea connector service.
type ServiceConfig struct {
	// Authorizer authorizes incoming requests.
	Authorizer authz.Authorizer
	// Backend stores Gitea connectors.
	Backend services.GiteaConnectors
	// Reader serves connector reads, typically from the auth cache.
	Reader services.GiteaConnectorsGetter
	// AuthServer drives login flows.
	AuthServer AuthServer
	// Emitter emits audit events.
	Emitter apievents.Emitter
	// Logger is the logger to use.
	Logger *slog.Logger
}

// CheckAndSetDefaults validates the config and fills in defaults.
func (c *ServiceConfig) CheckAndSetDefaults() error {
	if c.Authorizer == nil {
		return trace.BadParameter("authorizer is required")
	}
	if c.Backend == nil {
		return trace.BadParameter("backend is required")
	}
	if c.Reader == nil {
		return trace.BadParameter("reader is required")
	}
	if c.AuthServer == nil {
		return trace.BadParameter("auth server is required")
	}
	if c.Emitter == nil {
		return trace.BadParameter("emitter is required")
	}
	if c.Logger == nil {
		c.Logger = slog.Default().With("component", "gitea")
	}
	return nil
}

// Service implements the GiteaConnectorService gRPC service.
type Service struct {
	giteaconnectorv1.UnimplementedGiteaConnectorServiceServer

	authorizer authz.Authorizer
	backend    services.GiteaConnectors
	reader     services.GiteaConnectorsGetter
	authServer AuthServer
	emitter    apievents.Emitter
	logger     *slog.Logger
}

// NewService returns a new Gitea connector service.
func NewService(cfg ServiceConfig) (*Service, error) {
	if err := cfg.CheckAndSetDefaults(); err != nil {
		return nil, trace.Wrap(err)
	}
	return &Service{
		authorizer: cfg.Authorizer,
		backend:    cfg.Backend,
		reader:     cfg.Reader,
		authServer: cfg.AuthServer,
		emitter:    cfg.Emitter,
		logger:     cfg.Logger,
	}, nil
}

// checkConnectorAccess checks access to Gitea connectors. Like the other
// auth connectors, access is also granted through the umbrella
// auth_connector kind.
func checkConnectorAccess(authCtx *authz.Context, verb string, additionalVerbs ...string) error {
	if err := authCtx.CheckAccessToKind(types.KindGitea, verb, additionalVerbs...); err != nil {
		if errUmbrella := authCtx.CheckAccessToKind(types.KindAuthConnector, verb, additionalVerbs...); errUmbrella != nil {
			return trace.Wrap(err)
		}
	}
	return nil
}

// authorizeWrite authorizes a mutating connector operation. Connector writes
// always require a fresh admin-action MFA challenge, like other auth
// connectors.
func (s *Service) authorizeWrite(ctx context.Context, verbs ...string) (*authz.Context, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := checkConnectorAccess(authCtx, verbs[0], verbs[1:]...); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}
	return authCtx, nil
}

// authorizeRead authorizes a read of connectors, requiring the stronger
// "read" verb and admin-action MFA when secrets are requested.
func (s *Service) authorizeRead(ctx context.Context, withSecrets bool) (*authz.Context, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := checkConnectorAccess(authCtx, types.VerbReadNoSecrets); err != nil {
		return nil, trace.Wrap(err)
	}
	if withSecrets {
		if err := checkConnectorAccess(authCtx, types.VerbRead); err != nil {
			return nil, trace.Wrap(err)
		}
		if err := authCtx.AuthorizeAdminActionAllowReusedMFA(); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	return authCtx, nil
}

// CreateGiteaConnector creates a new Gitea connector.
func (s *Service) CreateGiteaConnector(ctx context.Context, req *giteaconnectorv1.CreateGiteaConnectorRequest) (*giteaconnectorv1.GiteaConnector, error) {
	authCtx, err := s.authorizeWrite(ctx, types.VerbCreate)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	connector := req.GetConnector()
	if err := services.ValidateGiteaConnector(connector); err != nil {
		return nil, trace.Wrap(err)
	}
	created, err := s.backend.CreateGiteaConnector(ctx, connector)
	s.emitConnectorEvent(ctx, authCtx, events.GiteaConnectorCreatedEvent, events.GiteaConnectorCreatedCode, connector.GetMetadata().GetName(), err)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return services.GiteaConnectorWithoutSecrets(created), nil
}

// UpdateGiteaConnector updates an existing Gitea connector.
func (s *Service) UpdateGiteaConnector(ctx context.Context, req *giteaconnectorv1.UpdateGiteaConnectorRequest) (*giteaconnectorv1.GiteaConnector, error) {
	authCtx, err := s.authorizeWrite(ctx, types.VerbUpdate)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	connector := req.GetConnector()
	if err := services.ValidateGiteaConnector(connector); err != nil {
		return nil, trace.Wrap(err)
	}
	updated, err := s.backend.UpdateGiteaConnector(ctx, connector)
	s.emitConnectorEvent(ctx, authCtx, events.GiteaConnectorUpdatedEvent, events.GiteaConnectorUpdatedCode, connector.GetMetadata().GetName(), err)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return services.GiteaConnectorWithoutSecrets(updated), nil
}

// UpsertGiteaConnector creates or replaces a Gitea connector.
func (s *Service) UpsertGiteaConnector(ctx context.Context, req *giteaconnectorv1.UpsertGiteaConnectorRequest) (*giteaconnectorv1.GiteaConnector, error) {
	authCtx, err := s.authorizeWrite(ctx, types.VerbCreate, types.VerbUpdate)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	connector := req.GetConnector()
	if err := services.ValidateGiteaConnector(connector); err != nil {
		return nil, trace.Wrap(err)
	}
	upserted, err := s.backend.UpsertGiteaConnector(ctx, connector)
	s.emitConnectorEvent(ctx, authCtx, events.GiteaConnectorCreatedEvent, events.GiteaConnectorCreatedCode, connector.GetMetadata().GetName(), err)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return services.GiteaConnectorWithoutSecrets(upserted), nil
}

// DeleteGiteaConnector deletes a Gitea connector.
func (s *Service) DeleteGiteaConnector(ctx context.Context, req *giteaconnectorv1.DeleteGiteaConnectorRequest) (*emptypb.Empty, error) {
	authCtx, err := s.authorizeWrite(ctx, types.VerbDelete)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	err = s.backend.DeleteGiteaConnector(ctx, req.GetName())
	s.emitConnectorEvent(ctx, authCtx, events.GiteaConnectorDeletedEvent, events.GiteaConnectorDeletedCode, req.GetName(), err)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return &emptypb.Empty{}, nil
}

// GetGiteaConnector returns a Gitea connector by name.
func (s *Service) GetGiteaConnector(ctx context.Context, req *giteaconnectorv1.GetGiteaConnectorRequest) (*giteaconnectorv1.GiteaConnector, error) {
	if _, err := s.authorizeRead(ctx, req.GetWithSecrets()); err != nil {
		return nil, trace.Wrap(err)
	}
	connector, err := s.reader.GetGiteaConnector(ctx, req.GetName(), req.GetWithSecrets())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connector, nil
}

// ListGiteaConnectors returns a page of Gitea connectors.
func (s *Service) ListGiteaConnectors(ctx context.Context, req *giteaconnectorv1.ListGiteaConnectorsRequest) (*giteaconnectorv1.ListGiteaConnectorsResponse, error) {
	if _, err := s.authorizeRead(ctx, req.GetWithSecrets()); err != nil {
		return nil, trace.Wrap(err)
	}
	connectors, next, err := s.reader.ListGiteaConnectors(ctx, int(req.GetPageSize()), req.GetPageToken(), req.GetWithSecrets())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return giteaconnectorv1.ListGiteaConnectorsResponse_builder{
		Connectors:    connectors,
		NextPageToken: next,
	}.Build(), nil
}

// CreateGiteaAuthRequest starts a Gitea login flow.
func (s *Service) CreateGiteaAuthRequest(ctx context.Context, req *giteaconnectorv1.CreateGiteaAuthRequestRequest) (*giteaconnectorv1.GiteaAuthRequest, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindGiteaRequest, types.VerbCreate); err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.AuthorizeAdminAction(); err != nil {
		return nil, trace.Wrap(err)
	}
	authReq := req.GetRequest()
	if authReq == nil {
		return nil, trace.BadParameter("missing auth request")
	}
	// The SSO test flow carries an arbitrary connector spec, so it requires
	// the permission to create connectors.
	if authReq.GetSsoTestFlow() {
		if err := checkConnectorAccess(authCtx, types.VerbCreate); err != nil {
			return nil, trace.Wrap(err)
		}
	}
	// Only the proxy can create web sessions via a Gitea connector.
	if authReq.GetCreateWebSession() && !authz.HasBuiltinRole(*authCtx, string(types.RoleProxy)) {
		return nil, trace.AccessDenied("this request can be only executed by a proxy")
	}
	// The authenticated-user flow is reserved for the auth server itself.
	if authReq.GetAuthenticatedUser() != "" {
		return nil, trace.AccessDenied("authenticated user flows cannot be started through the API")
	}

	created, err := s.authServer.CreateGiteaAuthRequest(ctx, authReq)
	if err != nil {
		if trace.IsNotFound(err) {
			// This flow is triggered via an unauthenticated endpoint, so
			// attempts with an invalid connector ID are not unusual. Keep
			// them out of the audit log.
			s.logger.InfoContext(ctx, "rejecting invalid Gitea auth request", "connector", authReq.GetConnectorId())
		} else {
			s.emitLoginFailure(ctx, err, authReq.GetSsoTestFlow())
		}
		return nil, trace.Wrap(err)
	}
	return created, nil
}

// GetGiteaAuthRequest returns a pending Gitea auth request.
func (s *Service) GetGiteaAuthRequest(ctx context.Context, req *giteaconnectorv1.GetGiteaAuthRequestRequest) (*giteaconnectorv1.GiteaAuthRequest, error) {
	authCtx, err := s.authorizer.Authorize(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if err := authCtx.CheckAccessToKind(types.KindGiteaRequest, types.VerbRead); err != nil {
		return nil, trace.Wrap(err)
	}
	authReq, err := s.authServer.GetGiteaAuthRequest(ctx, req.GetStateToken())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return authReq, nil
}

// emitConnectorEvent emits a connector create, update or delete audit event.
// The GitHub connector event payloads are reused: they carry only resource
// and user metadata, which are identical for Gitea.
func (s *Service) emitConnectorEvent(ctx context.Context, authCtx *authz.Context, eventType, code, name string, opErr error) {
	meta := apievents.Metadata{Type: eventType, Code: code}
	resource := apievents.ResourceMetadata{Name: name}
	var event apievents.AuditEvent
	switch eventType {
	case events.GiteaConnectorCreatedEvent:
		event = &apievents.GithubConnectorCreate{
			Metadata:           meta,
			UserMetadata:       authCtx.GetUserMetadata(),
			ResourceMetadata:   resource,
			ConnectionMetadata: authz.ConnectionMetadata(ctx),
		}
	case events.GiteaConnectorUpdatedEvent:
		event = &apievents.GithubConnectorUpdate{
			Metadata:           meta,
			UserMetadata:       authCtx.GetUserMetadata(),
			ResourceMetadata:   resource,
			ConnectionMetadata: authz.ConnectionMetadata(ctx),
		}
	case events.GiteaConnectorDeletedEvent:
		event = &apievents.GithubConnectorDelete{
			Metadata:           meta,
			UserMetadata:       authCtx.GetUserMetadata(),
			ResourceMetadata:   resource,
			ConnectionMetadata: authz.ConnectionMetadata(ctx),
		}
	default:
		return
	}
	if opErr != nil {
		// Failed operations are not recorded as connector changes, matching
		// the GitHub connector behavior.
		return
	}
	if err := s.emitter.EmitAuditEvent(ctx, event); err != nil {
		s.logger.WarnContext(ctx, "Failed to emit Gitea connector event", "event", eventType, "error", err)
	}
}

// emitLoginFailure records a failed attempt to start a login flow.
func (s *Service) emitLoginFailure(ctx context.Context, loginErr error, testFlow bool) {
	code := events.UserSSOLoginFailureCode
	if testFlow {
		code = events.UserSSOTestFlowLoginFailureCode
	}
	if err := s.emitter.EmitAuditEvent(ctx, &apievents.UserLogin{
		Metadata: apievents.Metadata{
			Type: events.UserLoginEvent,
			Code: code,
		},
		Method: events.LoginMethodGitea,
		Status: apievents.Status{
			Success:     false,
			Error:       trace.Unwrap(loginErr).Error(),
			UserMessage: loginErr.Error(),
		},
		ConnectionMetadata: authz.ConnectionMetadata(ctx),
	}); err != nil {
		s.logger.WarnContext(ctx, "Failed to emit Gitea login failure event", "error", err)
	}
}
