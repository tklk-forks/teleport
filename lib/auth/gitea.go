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
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"
	"golang.org/x/oauth2"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/gravitational/teleport"
	"github.com/gravitational/teleport/api/constants"
	apidefaults "github.com/gravitational/teleport/api/defaults"
	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/api/types"
	apievents "github.com/gravitational/teleport/api/types/events"
	"github.com/gravitational/teleport/api/utils/keys/hardwarekey"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/authz"
	"github.com/gravitational/teleport/lib/client/sso"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/events"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/loginrule"
	"github.com/gravitational/teleport/lib/services"
	"github.com/gravitational/teleport/lib/utils"
)

// ErrGiteaNoRoles is returned when a user authenticated via Gitea has no
// roles assigned in Teleport.
var ErrGiteaNoRoles = trace.AccessDenied("Gitea user has no Teleport-assigned roles.")

const (
	// giteaAuthPath is the Gitea OAuth2 authorization endpoint, relative to
	// the connector's endpoint URL.
	giteaAuthPath = "login/oauth/authorize"
	// giteaTokenPath is the Gitea OAuth2 token endpoint, relative to the
	// connector's endpoint URL.
	giteaTokenPath = "login/oauth/access_token"
	// giteaTeamsPageSize is the page size requested from the teams API.
	giteaTeamsPageSize = 50
	// giteaMaxPages is the maximum number of team pages that will be fetched.
	giteaMaxPages = 99
	// giteaTeamsTrait is the trait that carries the names of the Gitea teams
	// the user belongs to.
	giteaTeamsTrait = "gitea_teams"
	// giteaEmailTrait is the trait that carries the user's Gitea email.
	giteaEmailTrait = "email"
)

// giteaScopes is the list of Gitea token scopes requested during the OAuth2
// flow. read:user is needed for /user, read:organization for /user/teams.
var giteaScopes = []string{"read:user", "read:organization"}

// CreateGiteaAuthRequest starts a Gitea OAuth2 login flow. It stores the
// request and returns it with the state token and redirect URL populated.
func (a *Server) CreateGiteaAuthRequest(ctx context.Context, req *giteaconnectorv1.GiteaAuthRequest) (*giteaconnectorv1.GiteaAuthRequest, error) {
	connector, err := a.getGiteaConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Requests for a web session originate from the proxy, so they are
	// trusted. Requests for a client session (tsh login) point the browser
	// away from the IdP or the web UI after authentication, so the redirect
	// must be validated.
	if !req.GetCreateWebSession() {
		ceremonyType := sso.CeremonyTypeLogin
		if req.GetSsoTestFlow() {
			ceremonyType = sso.CeremonyTypeTest
		}
		if err := sso.ValidateClientRedirect(req.GetClientRedirectUrl(), ceremonyType, services.GiteaClientRedirectSettings(connector.GetSpec())); err != nil {
			return nil, trace.Wrap(err, InvalidClientRedirectErrorMessage)
		}
	}

	stateToken, err := utils.CryptoRandomHex(defaults.TokenLenBytes)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	req.SetStateToken(stateToken)

	config := newGiteaOAuth2Config(connector.GetSpec())
	req.SetRedirectUrl(config.AuthCodeURL(stateToken))
	req.SetExpires(timestamppb.New(a.GetClock().Now().UTC().Add(defaults.GithubAuthRequestTTL)))
	a.logger.DebugContext(ctx, "Creating Gitea auth request", "redirect_url", req.GetRedirectUrl())

	if err := a.Services.CreateGiteaAuthRequest(ctx, req); err != nil {
		return nil, trace.Wrap(err)
	}
	return req, nil
}

// getGiteaConnector resolves the connector for an auth request. In the SSO
// test flow and the authenticated-user flow the connector is taken from the
// request itself, otherwise it is loaded from the backend with its secret.
func (a *Server) getGiteaConnector(ctx context.Context, req *giteaconnectorv1.GiteaAuthRequest) (*giteaconnectorv1.GiteaConnector, error) {
	if req.GetConnectorId() == "" {
		return nil, trace.BadParameter("connector_id cannot be empty")
	}
	if req.GetSsoTestFlow() || req.GetAuthenticatedUser() != "" {
		if !req.HasConnectorSpec() {
			return nil, trace.BadParameter("connector_spec cannot be nil for the SSO test flow or the authenticated user flow")
		}
		connector := giteaconnectorv1.GiteaConnector_builder{
			Kind:     types.KindGitea,
			Version:  types.V1,
			Metadata: headerv1.Metadata_builder{Name: req.GetConnectorId()}.Build(),
			Spec:     req.GetConnectorSpec(),
		}.Build()
		if err := services.ValidateGiteaConnector(connector); err != nil {
			return nil, trace.Wrap(err)
		}
		return connector, nil
	}

	connector, err := a.GetGiteaConnector(ctx, req.GetConnectorId(), true)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return connector, nil
}

func newGiteaOAuth2Config(spec *giteaconnectorv1.GiteaConnectorSpec) oauth2.Config {
	return oauth2.Config{
		ClientID:     spec.GetClientId(),
		ClientSecret: spec.GetClientSecret(),
		RedirectURL:  spec.GetRedirectUrl(),
		Scopes:       giteaScopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:   fmt.Sprintf("%s/%s", spec.GetEndpointUrl(), giteaAuthPath),
			TokenURL:  fmt.Sprintf("%s/%s", spec.GetEndpointUrl(), giteaTokenPath),
			AuthStyle: oauth2.AuthStyleInParams,
		},
	}
}

// ValidateGiteaAuthCallback validates the Gitea OAuth2 callback, creates or
// updates the Teleport user and issues a web session or certificates.
func (a *Server) ValidateGiteaAuthCallback(ctx context.Context, q url.Values) (*authclient.GiteaAuthResponse, error) {
	diagCtx := NewSSODiagContext(types.KindGitea, a)
	logger := a.logger.With(teleport.ComponentKey, "gitea")

	event := &apievents.UserLogin{
		Metadata: apievents.Metadata{
			Type: events.UserLoginEvent,
		},
		Method:             events.LoginMethodGitea,
		ConnectionMetadata: authz.ConnectionMetadata(ctx),
	}

	auth, err := a.validateGiteaAuthRedirect(ctx, diagCtx, q, logger)
	diagCtx.Info.Error = trace.UserMessage(err)
	event.AppliedLoginRules = diagCtx.Info.AppliedLoginRules

	diagCtx.WriteToBackend(ctx)

	if claims := diagCtx.Info.GithubClaims; claims != nil {
		attributes, err := apievents.EncodeMapStrings(claims.OrganizationToTeams)
		if err != nil {
			event.Status.UserMessage = fmt.Sprintf("Failed to encode identity attributes: %v", err.Error())
			logger.DebugContext(ctx, "Failed to encode identity attributes", "error", err)
		} else {
			event.IdentityAttributes = attributes
		}
	}

	if err != nil {
		event.Code = events.UserSSOLoginFailureCode
		if diagCtx.Info.TestFlow {
			event.Code = events.UserSSOTestFlowLoginFailureCode
		}
		event.Status.Success = false
		event.Status.Error = trace.Unwrap(err).Error()
		event.Status.UserMessage = err.Error()
		if err := a.emitter.EmitAuditEvent(ctx, event); err != nil {
			logger.WarnContext(ctx, "Failed to emit Gitea login failed event", "error", err)
		}
		return nil, trace.Wrap(err)
	}

	event.Code = events.UserSSOLoginCode
	if diagCtx.Info.TestFlow {
		event.Code = events.UserSSOTestFlowLoginCode
	}
	event.Status.Success = true
	event.User = auth.Username
	if err := a.emitter.EmitAuditEvent(ctx, event); err != nil {
		logger.WarnContext(ctx, "Failed to emit Gitea login event", "error", err)
	}
	return auth, nil
}

func (a *Server) validateGiteaAuthRedirect(ctx context.Context, diagCtx *SSODiagContext, q url.Values, logger *slog.Logger) (*authclient.GiteaAuthResponse, error) {
	if errParam := q.Get("error"); errParam != "" {
		// Try to find the request so the error gets logged against it.
		if state := q.Get("state"); state != "" {
			diagCtx.RequestID = state
			if req, err := a.Services.GetGiteaAuthRequest(ctx, state); err == nil {
				diagCtx.Info.TestFlow = req.GetSsoTestFlow()
			}
		}
		errDesc := q.Get("error_description")
		oauthErr := trace.OAuth2("invalid_request", errParam, q)
		return nil, trace.WithUserMessage(oauthErr, "Gitea returned error: %v [%v]", errDesc, errParam)
	}

	code := q.Get("code")
	if code == "" {
		oauthErr := trace.OAuth2("invalid_request", "code query param must be set", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from Gitea.")
	}
	stateToken := q.Get("state")
	if stateToken == "" {
		oauthErr := trace.OAuth2("invalid_request", "missing state query param", q)
		return nil, trace.WithUserMessage(oauthErr, "Invalid parameters received from Gitea.")
	}
	diagCtx.RequestID = stateToken

	req, err := a.Services.GetGiteaAuthRequest(ctx, stateToken)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get Gitea auth request.")
	}
	diagCtx.Info.TestFlow = req.GetSsoTestFlow()

	if req.GetAuthenticatedUser() != "" {
		return a.validateGiteaAuthCallbackForAuthenticatedUser(ctx, code, req, diagCtx, logger)
	}

	connector, err := a.getGiteaConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get Gitea connector.")
	}
	spec := connector.GetSpec()
	diagCtx.Info.GithubTeamsToRoles = services.GiteaTeamsToRoles(spec)
	logger.DebugContext(ctx, "Connector found",
		"connector", connector.GetMetadata().GetName(),
		"teams_to_roles", diagCtx.Info.GithubTeamsToRoles,
	)

	userResp, teamsResp, err := a.getGiteaUserAndTeams(ctx, spec, code, diagCtx, logger)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	claims, err := populateGiteaClaims(userResp, teamsResp)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to build claims from the Gitea API response.")
	}
	logger.DebugContext(ctx, "Retrieved Gitea claims",
		slog.Group("claims",
			slog.String("user_name", claims.Username),
			slog.String("user_id", claims.UserID),
			slog.Any("teams", claims.Teams),
			slog.Any("organization_to_teams", claims.OrganizationToTeams),
		),
	)
	diagCtx.Info.GithubClaims = claims

	params, err := a.calculateGiteaUser(ctx, diagCtx, connector, claims, userResp, req)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to calculate user attributes.")
	}
	diagCtx.Info.CreateUserParams = &types.CreateUserParams{
		ConnectorName: params.ConnectorName,
		Username:      params.Username,
		Roles:         params.Roles,
		Traits:        params.Traits,
		SessionTTL:    types.Duration(params.SessionTTL),
	}

	user, err := a.createGiteaUser(ctx, params, req.GetSsoTestFlow())
	if err != nil {
		return nil, trace.Wrap(err, "Failed to create user from provided parameters.")
	}
	if err := a.CallLoginHooks(ctx, user); err != nil {
		return nil, trace.Wrap(err)
	}
	userState, err := a.GetUserOrLoginState(ctx, user.GetName())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if len(userState.GetRoles()) == 0 {
		return nil, trace.Wrap(ErrGiteaNoRoles)
	}

	// In the test flow skip signing and creating web sessions.
	if req.GetSsoTestFlow() {
		diagCtx.Info.Success = true
		return &authclient.GiteaAuthResponse{
			Req:      GiteaAuthRequestFromProto(req),
			Identity: userResp.makeExternalIdentity(params.ConnectorName),
			Username: params.Username,
		}, nil
	}

	sessionRoles, err := services.FetchRoles(userState.GetRoles(), a, userState.GetTraits())
	if err != nil {
		return nil, trace.Wrap(err)
	}
	sessionTTL := utils.MinTTL(sessionRoles.AdjustSessionTTL(apidefaults.MaxCertDuration), params.SessionTTL)

	return a.makeGiteaAuthResponse(ctx, req, userState, userResp, sessionTTL)
}

func (a *Server) validateGiteaAuthCallbackForAuthenticatedUser(
	ctx context.Context,
	code string,
	req *giteaconnectorv1.GiteaAuthRequest,
	diagCtx *SSODiagContext,
	logger *slog.Logger,
) (*authclient.GiteaAuthResponse, error) {
	connector, err := a.getGiteaConnector(ctx, req)
	if err != nil {
		return nil, trace.Wrap(err, "Failed to get Gitea connector.")
	}
	client, err := a.getGiteaAPIClient(ctx, connector.GetSpec(), code, diagCtx, logger)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	giteaUser, err := client.getUser(ctx)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	// Attach the new (but secondary) identity.
	teleportUser, err := a.GetUser(ctx, req.GetAuthenticatedUser(), false)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	teleportUser.SetGithubIdentities([]types.ExternalIdentity{
		giteaUser.makeExternalIdentity(req.GetConnectorId()),
	})

	userState, err := a.ulsGenerator.Refresh(ctx, teleportUser, a.UserLoginStates)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return a.makeGiteaAuthResponse(ctx, req, userState, giteaUser, req.GetCertTtl().AsDuration())
}

func (a *Server) getGiteaAPIClient(
	ctx context.Context,
	spec *giteaconnectorv1.GiteaConnectorSpec,
	code string,
	diagCtx *SSODiagContext,
	logger *slog.Logger,
) (*giteaAPIClient, error) {
	config := newGiteaOAuth2Config(spec)

	token, err := config.Exchange(ctx, code)
	if err != nil {
		return nil, trace.Wrap(err, "Requesting Gitea OAuth2 token failed.")
	}
	// Gitea omits the scope field from the token response when no scope was
	// granted, so a missing scope is not an error here.
	scope, _ := token.Extra("scope").(string)
	diagCtx.Info.GithubTokenInfo = &types.GithubTokenInfo{
		TokenType: token.TokenType,
		Expires:   token.ExpiresIn,
		Scope:     scope,
	}
	logger.DebugContext(ctx, "Obtained Gitea OAuth2 token",
		"type", token.TokenType, "expires", token.ExpiresIn, "scope", scope)

	httpClient, err := defaults.HTTPClient()
	if err != nil {
		return nil, trace.Wrap(err)
	}
	return newGiteaAPIClient(spec.GetApiEndpointUrl(), token.AccessToken, httpClient)
}

func (a *Server) getGiteaUserAndTeams(
	ctx context.Context,
	spec *giteaconnectorv1.GiteaConnectorSpec,
	code string,
	diagCtx *SSODiagContext,
	logger *slog.Logger,
) (*GiteaUserResponse, []GiteaTeamResponse, error) {
	if a.GiteaUserAndTeamsOverride != nil {
		// Allow tests to override the user and teams response instead of
		// calling out to Gitea.
		return a.GiteaUserAndTeamsOverride()
	}

	client, err := a.getGiteaAPIClient(ctx, spec, code, diagCtx, logger)
	if err != nil {
		return nil, nil, trace.Wrap(err)
	}
	userResp, err := client.getUser(ctx)
	if err != nil {
		return nil, nil, trace.Wrap(err, "failed to query Gitea user info")
	}
	teamsResp, err := client.getTeams(ctx)
	if err != nil {
		return nil, nil, trace.Wrap(err, "failed to query Gitea user teams")
	}
	logger.DebugContext(ctx, "Retrieved teams for Gitea user.", "num_teams", len(teamsResp), "gitea_user", userResp.Login)
	return userResp, teamsResp, nil
}

func (a *Server) calculateGiteaUser(
	ctx context.Context,
	diagCtx *SSODiagContext,
	connector *giteaconnectorv1.GiteaConnector,
	claims *types.GithubClaims,
	user *GiteaUserResponse,
	req *giteaconnectorv1.GiteaAuthRequest,
) (*CreateUserParams, error) {
	p := CreateUserParams{
		ConnectorName: connector.GetMetadata().GetName(),
		Username:      claims.Username,
		UserID:        claims.UserID,
	}

	p.Roles = services.MapGiteaClaims(connector.GetSpec(), *claims)
	p.Traits = map[string][]string{
		constants.TraitLogins: {p.Username},
		giteaTeamsTrait:       claims.Teams,
	}
	if user.Email != "" {
		p.Traits[giteaEmailTrait] = []string{user.Email}
	}

	evaluationOutput, err := a.GetLoginRuleEvaluator().Evaluate(ctx, &loginrule.EvaluationInput{
		Traits: p.Traits,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	p.Traits = evaluationOutput.Traits
	diagCtx.Info.AppliedLoginRules = evaluationOutput.AppliedRules
	p.KubeGroups = p.Traits[constants.TraitKubeGroups]
	p.KubeUsers = p.Traits[constants.TraitKubeUsers]

	// Pick the smaller of the role session TTL and the requested TTL.
	roles, err := services.FetchRolesWithContext(p.Roles, a, services.RoleTemplateContext{
		Username: p.Username,
		Traits:   p.Traits,
	})
	if err != nil {
		return nil, trace.Wrap(err)
	}
	roleTTL := roles.AdjustSessionTTL(apidefaults.MaxCertDuration)
	p.SessionTTL = utils.MinTTL(roleTTL, req.GetCertTtl().AsDuration())

	return &p, nil
}

// createGiteaUser creates or updates the dynamic Teleport user backing a
// Gitea identity. The identity is recorded in the GithubIdentities list
// because the user resource has no dedicated field for Gitea; the
// CreatedBy connector type distinguishes the two providers.
func (a *Server) createGiteaUser(ctx context.Context, p *CreateUserParams, dryRun bool) (types.User, error) {
	a.logger.DebugContext(ctx, "Generating dynamic Gitea identity",
		"connector_name", p.ConnectorName,
		"user_name", p.Username,
		"roles", p.Roles,
		"dry_run", dryRun,
	)

	expires := a.GetClock().Now().UTC().Add(p.SessionTTL)
	user := &types.UserV2{
		Kind:    types.KindUser,
		Version: types.V2,
		Metadata: types.Metadata{
			Name:      p.Username,
			Namespace: apidefaults.Namespace,
			Expires:   &expires,
		},
		Spec: types.UserSpecV2{
			Roles:  p.Roles,
			Traits: p.Traits,
			GithubIdentities: []types.ExternalIdentity{{
				ConnectorID: p.ConnectorName,
				Username:    p.Username,
				UserID:      p.UserID,
			}},
			CreatedBy: types.CreatedBy{
				User: types.UserRef{Name: teleport.UserSystem},
				Time: a.GetClock().Now().UTC(),
				Connector: &types.ConnectorRef{
					Type:     constants.Gitea,
					ID:       p.ConnectorName,
					Identity: p.Username,
				},
			},
		},
	}
	if dryRun {
		return user, nil
	}

	existingUser, err := a.Services.GetUser(ctx, p.Username, false)
	if err != nil && !trace.IsNotFound(err) {
		return nil, trace.Wrap(err)
	}
	if existingUser != nil {
		ref := user.GetCreatedBy().Connector
		if !ref.IsSameProvider(existingUser.GetCreatedBy().Connector) {
			return nil, trace.AlreadyExists("local user %q already exists and is not a Gitea user",
				existingUser.GetName())
		}
		user.SetRevision(existingUser.GetRevision())
		if _, err := a.UpdateUser(ctx, user); err != nil {
			return nil, trace.Wrap(err)
		}
		return user, nil
	}
	if _, err := a.CreateUser(ctx, user); err != nil {
		return nil, trace.Wrap(err)
	}
	return user, nil
}

func (a *Server) makeGiteaAuthResponse(
	ctx context.Context,
	req *giteaconnectorv1.GiteaAuthRequest,
	userState services.UserState,
	giteaUser *GiteaUserResponse,
	sessionTTL time.Duration,
) (*authclient.GiteaAuthResponse, error) {
	auth := authclient.GiteaAuthResponse{
		Req:      GiteaAuthRequestFromProto(req),
		Identity: giteaUser.makeExternalIdentity(req.GetConnectorId()),
		Username: userState.GetName(),
	}

	if req.GetCreateWebSession() {
		session, err := a.CreateWebSessionFromReq(ctx, NewWebSessionRequest{
			User:                 userState.GetName(),
			Roles:                userState.GetRoles(),
			Traits:               userState.GetTraits(),
			SessionTTL:           sessionTTL,
			LoginTime:            a.clock.Now().UTC(),
			LoginIP:              req.GetClientLoginIp(),
			LoginUserAgent:       req.GetClientUserAgent(),
			AttestWebSession:     true,
			CreateDeviceWebToken: true,
			Scope:                req.GetScope(),
		})
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create web session.")
		}
		auth.Session = session
	}

	if len(req.GetSshPublicKey()) != 0 || len(req.GetTlsPublicKey()) != 0 {
		sshAttestation, err := services.UnmarshalGiteaAttestationStatement(req.GetSshAttestationStatement())
		if err != nil {
			return nil, trace.Wrap(err, "Failed to parse SSH attestation statement.")
		}
		tlsAttestation, err := services.UnmarshalGiteaAttestationStatement(req.GetTlsAttestationStatement())
		if err != nil {
			return nil, trace.Wrap(err, "Failed to parse TLS attestation statement.")
		}
		sshCert, tlsCert, err := a.CreateSessionCerts(ctx, &SessionCertsRequest{
			UserState:               userState,
			SessionTTL:              sessionTTL,
			SSHPubKey:               req.GetSshPublicKey(),
			TLSPubKey:               req.GetTlsPublicKey(),
			SSHAttestationStatement: hardwarekey.AttestationStatementFromProto(sshAttestation),
			TLSAttestationStatement: hardwarekey.AttestationStatementFromProto(tlsAttestation),
			Compatibility:           req.GetCompatibility(),
			RouteToCluster:          req.GetRouteToCluster(),
			KubernetesCluster:       req.GetKubernetesCluster(),
			LoginIP:                 req.GetClientLoginIp(),
			Scope:                   req.GetScope(),
		})
		if err != nil {
			return nil, trace.Wrap(err, "Failed to create session certificate.")
		}
		clusterName, err := a.GetClusterName(ctx)
		if err != nil {
			return nil, trace.Wrap(err, "Failed to obtain cluster name.")
		}
		auth.Cert = sshCert
		auth.TLSCert = tlsCert

		authority, err := a.GetCertAuthority(ctx, types.CertAuthID{
			Type:       types.HostCA,
			DomainName: clusterName.GetClusterName(),
		}, false)
		if err != nil {
			return nil, trace.Wrap(err, "Failed to obtain cluster's host CA.")
		}
		auth.HostSigners = append(auth.HostSigners, authority)
	}

	if o, err := a.ClientOptionsForLogin(userState); err == nil {
		auth.ClientOptions = o
	} else {
		a.logger.WarnContext(ctx, "Failed to calculate client options for Gitea login", "username", userState.GetName(), "error", err)
	}
	return &auth, nil
}

// GiteaAuthRequestFromProto converts a stored auth request to the JSON
// representation returned to the proxy.
func GiteaAuthRequestFromProto(req *giteaconnectorv1.GiteaAuthRequest) authclient.GiteaAuthRequest {
	return authclient.GiteaAuthRequest{
		ConnectorID:       req.GetConnectorId(),
		SSHPubKey:         req.GetSshPublicKey(),
		TLSPubKey:         req.GetTlsPublicKey(),
		CSRFToken:         req.GetCsrfToken(),
		CreateWebSession:  req.GetCreateWebSession(),
		ClientRedirectURL: req.GetClientRedirectUrl(),
	}
}

// populateGiteaClaims builds claims from the Gitea user and team API
// responses. Organizations are keyed by name and teams by name, because
// Gitea exposes neither an organization login nor a team slug.
func populateGiteaClaims(user *GiteaUserResponse, teams []GiteaTeamResponse) (*types.GithubClaims, error) {
	if user == nil || user.Login == "" {
		return nil, trace.AccessDenied("Gitea user response has no login")
	}
	orgToTeams := make(map[string][]string)
	teamList := make([]string, 0, len(teams))
	for _, team := range teams {
		org := team.Organization.Name
		if org == "" {
			org = team.Organization.UserName
		}
		if org == "" || team.Name == "" {
			continue
		}
		orgToTeams[org] = append(orgToTeams[org], team.Name)
		teamList = append(teamList, team.Name)
	}
	if len(orgToTeams) == 0 {
		return nil, trace.AccessDenied("list of user teams is empty, did you grant access?")
	}
	return &types.GithubClaims{
		Username:            user.Login,
		UserID:              user.getIDStr(),
		OrganizationToTeams: orgToTeams,
		Teams:               teamList,
	}, nil
}

// GiteaUserResponse is the relevant part of the Gitea GET /user response.
type GiteaUserResponse struct {
	// Login is the username.
	Login string `json:"login"`
	// ID is the numeric user ID.
	ID int64 `json:"id"`
	// Email is the primary email address.
	Email string `json:"email"`
}

func (r GiteaUserResponse) getIDStr() string {
	return strconv.FormatInt(r.ID, 10)
}

func (r GiteaUserResponse) makeExternalIdentity(connectorID string) types.ExternalIdentity {
	return types.ExternalIdentity{
		ConnectorID: connectorID,
		Username:    r.Login,
		UserID:      r.getIDStr(),
	}
}

// GiteaTeamResponse is a single entry of the Gitea GET /user/teams response.
type GiteaTeamResponse struct {
	// ID is the numeric team ID.
	ID int64 `json:"id"`
	// Name is the team name. Gitea teams have no slug.
	Name string `json:"name"`
	// Organization is the organization the team belongs to.
	Organization GiteaOrgResponse `json:"organization"`
}

// GiteaOrgResponse is the organization embedded in a team response.
type GiteaOrgResponse struct {
	// Name is the organization name.
	Name string `json:"name"`
	// UserName is the deprecated alias of Name kept by older Gitea versions.
	UserName string `json:"username"`
}

// giteaAPIClient is a tiny wrapper around the Gitea REST API calls needed
// during login.
type giteaAPIClient struct {
	token       string
	apiEndpoint *url.URL
	client      *http.Client
}

func newGiteaAPIClient(apiEndpoint, token string, client *http.Client) (*giteaAPIClient, error) {
	u, err := url.Parse(apiEndpoint)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, trace.BadParameter("invalid Gitea API endpoint URL %q", apiEndpoint)
	}
	u.Path = strings.TrimRight(u.Path, "/")
	return &giteaAPIClient{token: token, apiEndpoint: u, client: client}, nil
}

// getUser returns the authenticated Gitea user.
func (c *giteaAPIClient) getUser(ctx context.Context) (*GiteaUserResponse, error) {
	body, _, err := c.get(ctx, c.apiEndpoint.JoinPath("user"))
	if err != nil {
		return nil, trace.Wrap(err)
	}
	var user GiteaUserResponse
	if err := json.Unmarshal(body, &user); err != nil {
		return nil, trace.Wrap(err)
	}
	return &user, nil
}

// getTeams returns every team the authenticated user belongs to. Pages are
// followed through the Link header, falling back to incrementing the page
// number when the header is absent.
func (c *giteaAPIClient) getTeams(ctx context.Context) ([]GiteaTeamResponse, error) {
	var result []GiteaTeamResponse
	page := 1
	next := c.apiEndpoint.JoinPath("user", "teams")
	next.RawQuery = url.Values{
		"limit": {strconv.Itoa(giteaTeamsPageSize)},
		"page":  {strconv.Itoa(page)},
	}.Encode()

	for count := 0; ; count++ {
		if count >= giteaMaxPages {
			return nil, trace.LimitExceeded("Gitea user belongs to too many teams: fetched the maximum of %d pages", giteaMaxPages)
		}
		body, nextLink, err := c.get(ctx, next)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		var teams []GiteaTeamResponse
		if err := json.Unmarshal(body, &teams); err != nil {
			return nil, trace.Wrap(err)
		}
		result = append(result, teams...)

		switch {
		case nextLink != "":
			u, err := url.Parse(nextLink)
			if err != nil {
				return nil, trace.Wrap(err)
			}
			if !u.IsAbs() {
				u = c.apiEndpoint.ResolveReference(u)
			}
			// Never follow a pagination link that points away from the
			// configured API endpoint.
			if u.Scheme != c.apiEndpoint.Scheme || u.Host != c.apiEndpoint.Host {
				return nil, trace.BadParameter("Gitea pagination link %q points outside of the API endpoint %q", nextLink, c.apiEndpoint.String())
			}
			next = u
		case len(teams) >= giteaTeamsPageSize:
			page++
			next = c.apiEndpoint.JoinPath("user", "teams")
			next.RawQuery = url.Values{
				"limit": {strconv.Itoa(giteaTeamsPageSize)},
				"page":  {strconv.Itoa(page)},
			}.Encode()
		default:
			return result, nil
		}
	}
}

// get performs an authenticated GET request and returns the body and the
// next page link, if any.
func (c *giteaAPIClient) get(ctx context.Context, u *url.URL) ([]byte, string, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	request.Header.Set("Authorization", "token "+c.token)
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	defer response.Body.Close()
	body, err := utils.ReadAtMost(response.Body, teleport.MaxHTTPResponseSize)
	if err != nil {
		return nil, "", trace.Wrap(err)
	}
	if response.StatusCode != http.StatusOK {
		return nil, "", trace.AccessDenied("bad response from Gitea API: %v %v", response.StatusCode, string(body))
	}
	return body, utils.ParseWebLinks(response).NextPage, nil
}

// validateGiteaAuthCallbackReq is the body of the legacy HTTP validate call.
type validateGiteaAuthCallbackReq struct {
	// Query is the callback query string.
	Query url.Values `json:"query"`
}

// giteaAuthRawResponse is the wire form of the validate call response.
type giteaAuthRawResponse struct {
	Username      string                      `json:"username"`
	Identity      types.ExternalIdentity      `json:"identity"`
	Session       json.RawMessage             `json:"session,omitempty"`
	Cert          []byte                      `json:"cert,omitempty"`
	TLSCert       []byte                      `json:"tls_cert,omitempty"`
	Req           authclient.GiteaAuthRequest `json:"req"`
	HostSigners   []json.RawMessage           `json:"host_signers"`
	ClientOptions authclient.ClientOptions    `json:"client_options"`
}

/*
validateGiteaAuthCallback validates a Gitea auth callback redirect.

	POST /:version/gitea/requests/validate

	Success response: giteaAuthRawResponse
*/
func (s *APIServer) validateGiteaAuthCallback(auth *ServerWithRoles, w http.ResponseWriter, r *http.Request, p httprouter.Params, version string) (any, error) {
	var req validateGiteaAuthCallbackReq
	if err := httplib.ReadJSON(r, &req); err != nil {
		return nil, trace.Wrap(err)
	}
	response, err := auth.ValidateGiteaAuthCallback(r.Context(), req.Query)
	if err != nil {
		return nil, trace.Wrap(err)
	}
	raw := giteaAuthRawResponse{
		Username:      response.Username,
		Identity:      response.Identity,
		Cert:          response.Cert,
		TLSCert:       response.TLSCert,
		Req:           response.Req,
		ClientOptions: response.ClientOptions,
	}
	if response.Session != nil {
		rawSession, err := services.MarshalWebSession(response.Session, services.WithVersion(version), services.PreserveRevision())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		raw.Session = rawSession
	}
	raw.HostSigners = make([]json.RawMessage, len(response.HostSigners))
	for i, ca := range response.HostSigners {
		data, err := services.MarshalCertAuthority(ca, services.WithVersion(version), services.PreserveRevision())
		if err != nil {
			return nil, trace.Wrap(err)
		}
		raw.HostSigners[i] = data
	}
	return &raw, nil
}
