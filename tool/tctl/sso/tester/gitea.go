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

package tester

import (
	"context"

	"github.com/gravitational/trace"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/durationpb"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/lib/auth/authclient"
	"github.com/gravitational/teleport/lib/client"
	"github.com/gravitational/teleport/lib/defaults"
	"github.com/gravitational/teleport/lib/services"
)

// giteaAuthRequestCreator is the subset of the Gitea connector client used
// to start a test flow.
type giteaAuthRequestCreator interface {
	CreateGiteaAuthRequest(ctx context.Context, req *giteaconnectorv1.CreateGiteaAuthRequestRequest, opts ...grpc.CallOption) (*giteaconnectorv1.GiteaAuthRequest, error)
}

func giteaTest(clt giteaAuthRequestCreator, connector *giteaconnectorv1.GiteaConnector) *AuthRequestInfo {
	ctx := context.Background()
	requestInfo := &AuthRequestInfo{}

	requestInfo.SSOLoginConsoleRequestFn = func(req client.SSOLoginConsoleReq) (*client.SSOLoginConsoleResponse, error) {
		if err := req.CheckAndSetDefaults(); err != nil {
			return nil, trace.Wrap(err)
		}
		request, err := clt.CreateGiteaAuthRequest(ctx, giteaconnectorv1.CreateGiteaAuthRequestRequest_builder{
			Request: giteaconnectorv1.GiteaAuthRequest_builder{
				ConnectorId:       req.ConnectorID + "-" + connector.GetMetadata().GetName(),
				SshPublicKey:      req.SSHPubKey,
				TlsPublicKey:      req.TLSPubKey,
				CertTtl:           durationpb.New(defaults.GithubAuthRequestTTL),
				CreateWebSession:  false,
				ClientRedirectUrl: req.RedirectURL,
				RouteToCluster:    req.RouteToCluster,
				SsoTestFlow:       true,
				ConnectorSpec:     connector.GetSpec(),
			}.Build(),
		}.Build())

		if request != nil {
			requestInfo.RequestID = request.GetStateToken()
		}
		requestInfo.RequestCreateErr = err
		if err != nil {
			return nil, trace.Wrap(err)
		}
		return &client.SSOLoginConsoleResponse{RedirectURL: request.GetRedirectUrl()}, nil
	}
	return requestInfo
}

func handleGiteaConnector(c *authclient.Client, connBytes []byte) (*AuthRequestInfo, error) {
	connector, err := services.UnmarshalGiteaConnector(connBytes)
	if err != nil {
		return nil, trace.Wrap(err, "Unable to load Gitea connector. Correct the definition and try again.")
	}
	if err := services.ValidateGiteaConnector(connector); err != nil {
		return nil, trace.Wrap(err, "Invalid Gitea connector. Correct the definition and try again.")
	}
	return giteaTest(c.GiteaConnectorClient(), connector), nil
}

func getGiteaDiagInfoFields(diag *types.SSODiagnosticInfo, debug bool) []string {
	return []string{
		GetDiagMessage(
			diag.GithubTokenInfo != nil,
			debug,
			FormatJSON("[Gitea] OAuth2 token info", diag.GithubTokenInfo),
		),
		GetDiagMessage(
			diag.GithubClaims != nil,
			true,
			FormatYAML("[Gitea] Received claims", diag.GithubClaims),
		),
		GetDiagMessage(
			diag.GithubTeamsToRoles != nil,
			true,
			FormatYAML("[Gitea] Connector team to roles mapping", diag.GithubTeamsToRoles),
		),
	}
}
