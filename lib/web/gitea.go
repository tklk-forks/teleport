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

package web

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"

	"github.com/gravitational/trace"
	"github.com/julienschmidt/httprouter"
	"google.golang.org/protobuf/types/known/durationpb"

	"github.com/gravitational/teleport/api/client/webclient"
	"github.com/gravitational/teleport/api/constants"
	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/client/sso"
	"github.com/gravitational/teleport/lib/httplib"
	"github.com/gravitational/teleport/lib/modules"
	"github.com/gravitational/teleport/lib/services"
)

// giteaSettings builds the authentication settings advertised to clients for
// a Gitea connector.
func giteaSettings(connector *giteaconnectorv1.GiteaConnector, cap types.AuthPreference, m modules.Modules) webclient.AuthenticationSettings {
	return webclient.AuthenticationSettings{
		Type: constants.Gitea,
		Gitea: &webclient.GiteaSettings{
			Name:        connector.GetMetadata().GetName(),
			Display:     connector.GetSpec().GetDisplay(),
			EndpointURL: services.GiteaEndpointURL(connector.GetSpec()),
		},
		// Local fallback / MFA.
		SecondFactor:            types.LegacySecondFactorFromSecondFactors(cap.GetSecondFactors()),
		PreferredLocalMFA:       cap.GetPreferredLocalMFA(),
		PrivateKeyPolicy:        cap.GetPrivateKeyPolicy(),
		PIVSlot:                 cap.GetPIVSlot(),
		PIVPINCacheTTL:          cap.GetPIVPINCacheTTL(),
		DeviceTrust:             deviceTrustSettings(cap, m),
		SignatureAlgorithmSuite: cap.GetSignatureAlgorithmSuite(),
	}
}

// getGiteaConnectors returns every Gitea connector, without secrets. Clusters
// whose auth server predates the Gitea connector return an empty list.
func getGiteaConnectors(ctx context.Context, clt authclient.ClientI) ([]*giteaconnectorv1.GiteaConnector, error) {
	connectors, err := services.GetAllGiteaConnectors(ctx, clt.GiteaConnectorServiceClient(), false)
	if err != nil {
		if trace.IsNotImplemented(err) {
			return nil, nil
		}
		return nil, trace.Wrap(err)
	}
	return connectors, nil
}

// giteaProvider converts a connector to the web config auth provider entry.
func giteaProvider(connector *giteaconnectorv1.GiteaConnector) webclient.WebConfigAuthProvider {
	return webclient.WebConfigAuthProvider{
		Type:        webclient.WebConfigAuthProviderGiteaType,
		WebAPIURL:   webclient.WebConfigAuthProviderGiteaURL,
		Name:        connector.GetMetadata().GetName(),
		DisplayName: connector.GetSpec().GetDisplay(),
	}
}

func (h *Handler) giteaLoginWeb(w http.ResponseWriter, r *http.Request, p httprouter.Params) string {
	logger := h.logger.With("auth", "gitea")
	logger.DebugContext(r.Context(), "Web login start")

	req, err := ParseSSORequestParams(r)
	if err != nil {
		logger.ErrorContext(r.Context(), "Failed to extract SSO parameters from request", "error", err)
		return sso.LoginFailedRedirectURL
	}
	remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logger.ErrorContext(r.Context(), "Failed to parse request remote address", "error", err)
		return sso.LoginFailedRedirectURL
	}

	response, err := h.cfg.ProxyClient.GiteaConnectorClient().CreateGiteaAuthRequest(r.Context(), giteaconnectorv1.CreateGiteaAuthRequestRequest_builder{
		Request: giteaconnectorv1.GiteaAuthRequest_builder{
			CsrfToken:         req.CSRFToken,
			ConnectorId:       req.ConnectorID,
			CreateWebSession:  true,
			ClientRedirectUrl: req.ClientRedirectURL,
			ClientLoginIp:     remoteAddr,
			ClientUserAgent:   r.UserAgent(),
			Scope:             req.Scope,
		}.Build(),
	}.Build())
	if err != nil {
		logger.ErrorContext(r.Context(), "Error creating auth request", "error", err)
		return sso.LoginFailedRedirectURL
	}
	return response.GetRedirectUrl()
}

func (h *Handler) giteaLoginConsole(w http.ResponseWriter, r *http.Request, p httprouter.Params) (any, error) {
	logger := h.logger.With("auth", "gitea")
	logger.DebugContext(r.Context(), "Console login start")

	req := new(client.SSOLoginConsoleReq)
	if err := httplib.ReadResourceJSON(r, req); err != nil {
		logger.ErrorContext(r.Context(), "Error reading json", "error", err)
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}
	if err := req.CheckAndSetDefaults(); err != nil {
		logger.ErrorContext(r.Context(), "Missing request parameters", "error", err)
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}
	remoteAddr, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		logger.ErrorContext(r.Context(), "Failed to parse request remote address", "error", err)
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}
	sshAttestation, err := services.MarshalGiteaAttestationStatement(req.SSHAttestationStatement.ToProto())
	if err != nil {
		logger.ErrorContext(r.Context(), "Failed to serialize SSH attestation statement", "error", err)
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}
	tlsAttestation, err := services.MarshalGiteaAttestationStatement(req.TLSAttestationStatement.ToProto())
	if err != nil {
		logger.ErrorContext(r.Context(), "Failed to serialize TLS attestation statement", "error", err)
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}

	response, err := h.cfg.ProxyClient.GiteaConnectorClient().CreateGiteaAuthRequest(r.Context(), giteaconnectorv1.CreateGiteaAuthRequestRequest_builder{
		Request: giteaconnectorv1.GiteaAuthRequest_builder{
			ConnectorId:             req.ConnectorID,
			SshPublicKey:            req.SSHPubKey,
			TlsPublicKey:            req.TLSPubKey,
			SshAttestationStatement: sshAttestation,
			TlsAttestationStatement: tlsAttestation,
			CertTtl:                 durationpb.New(req.CertTTL),
			ClientRedirectUrl:       req.RedirectURL,
			Compatibility:           req.Compatibility,
			RouteToCluster:          req.RouteToCluster,
			KubernetesCluster:       req.KubernetesCluster,
			ClientLoginIp:           remoteAddr,
			Scope:                   req.Scope,
		}.Build(),
	}.Build())
	if err != nil {
		logger.ErrorContext(r.Context(), "Failed to create Gitea auth request", "error", err)
		if strings.Contains(err.Error(), auth.InvalidClientRedirectErrorMessage) {
			return nil, trace.AccessDenied("%s", SSOLoginFailureInvalidRedirect)
		}
		return nil, trace.AccessDenied("%s", SSOLoginFailureMessage)
	}
	return &client.SSOLoginConsoleResponse{
		RedirectURL: response.GetRedirectUrl(),
	}, nil
}

func (h *Handler) giteaCallback(w http.ResponseWriter, r *http.Request, p httprouter.Params) string {
	logger := h.logger.With("auth", "gitea")
	logger.DebugContext(r.Context(), "Callback start", "query", r.URL.Query())

	response, err := h.cfg.ProxyClient.ValidateGiteaAuthCallback(r.Context(), r.URL.Query())
	if err != nil {
		logger.ErrorContext(r.Context(), "Error while processing callback", "error", err)

		// Try to find the auth request, which bears the original client
		// redirect URL, and use it to terminate the failed flow immediately.
		if requestID := r.URL.Query().Get("state"); requestID != "" {
			request, errGet := h.cfg.ProxyClient.GiteaConnectorClient().GetGiteaAuthRequest(r.Context(), giteaconnectorv1.GetGiteaAuthRequestRequest_builder{
				StateToken: requestID,
			}.Build())
			if errGet == nil && !request.GetCreateWebSession() {
				if redURL, errEnc := RedirectURLWithError(request.GetClientRedirectUrl(), err); errEnc == nil {
					return redURL.String()
				}
			}
		}
		if errors.Is(err, auth.ErrGiteaNoRoles) {
			return sso.LoginFailedUnauthorizedRedirectURL
		}
		return sso.LoginFailedBadCallbackRedirectURL
	}

	// If a web session was created, set the session cookie and redirect to
	// the original URL.
	if response.Req.CreateWebSession {
		logger.InfoContext(r.Context(), "Redirecting to web browser")

		res := &SSOCallbackResponse{
			CSRFToken:         response.Req.CSRFToken,
			Username:          response.Username,
			SessionName:       response.Session.GetName(),
			SessionExpiry:     response.Session.Expiry(),
			ClientRedirectURL: response.Req.ClientRedirectURL,
		}
		if err := SSOSetWebSessionAndRedirectURL(w, r, res, true); err != nil {
			logger.ErrorContext(r.Context(), "Error setting web session.", "error", err)
			return sso.LoginFailedRedirectURL
		}
		if dwt := response.Session.GetDeviceWebToken(); dwt != nil {
			logger.DebugContext(r.Context(), "Gitea WebSession created with device web token")
			redirectPath, err := BuildDeviceWebRedirectPath(dwt, res.ClientRedirectURL)
			if err != nil {
				logger.DebugContext(r.Context(), "Invalid device web token", "error", err)
			}
			return redirectPath
		}
		return res.ClientRedirectURL
	}

	logger.InfoContext(r.Context(), "Callback is redirecting to console login")
	if len(response.Req.SSHPubKey)+len(response.Req.TLSPubKey) == 0 {
		logger.ErrorContext(r.Context(), "Not a web or console login request")
		return sso.LoginFailedRedirectURL
	}
	redirectURL, err := ConstructSSHResponse(AuthParams{
		ClientRedirectURL: response.Req.ClientRedirectURL,
		Username:          response.Username,
		Identity:          response.Identity,
		Session:           response.Session,
		Cert:              response.Cert,
		TLSCert:           response.TLSCert,
		HostSigners:       response.HostSigners,
		FIPS:              h.cfg.FIPS,
		ClientOptions:     response.ClientOptions,
	})
	if err != nil {
		logger.ErrorContext(r.Context(), "Error constructing ssh response", "error", err)
		return sso.LoginFailedRedirectURL
	}
	return redirectURL.String()
}
