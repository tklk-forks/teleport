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

package services

import (
	"context"
	"net/url"
	"strings"

	"github.com/gravitational/trace"
	"google.golang.org/protobuf/proto"

	"github.com/gravitational/teleport/api/constants"
	attestationv1 "github.com/gravitational/teleport/api/gen/proto/go/attestation/v1"
	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	"github.com/gravitational/teleport/api/types"
	"github.com/gravitational/teleport/api/utils"
)

// GiteaAPIPathSuffix is appended to a Gitea connector's endpoint URL to build
// the default REST API endpoint URL.
const GiteaAPIPathSuffix = "/api/v1"

// GiteaConnectorsGetter defines read-only access to Gitea connectors.
type GiteaConnectorsGetter interface {
	// GetGiteaConnector returns a Gitea connector by name. The client secret is
	// only included when withSecrets is true.
	GetGiteaConnector(ctx context.Context, name string, withSecrets bool) (*giteaconnectorv1.GiteaConnector, error)
	// ListGiteaConnectors returns a page of Gitea connectors. Client secrets are
	// only included when withSecrets is true.
	ListGiteaConnectors(ctx context.Context, pageSize int, pageToken string, withSecrets bool) ([]*giteaconnectorv1.GiteaConnector, string, error)
}

// GiteaConnectors defines storage of Gitea connectors and of the auth
// requests created while users log in through them.
type GiteaConnectors interface {
	GiteaConnectorsGetter
	// CreateGiteaConnector creates a new Gitea connector.
	CreateGiteaConnector(ctx context.Context, connector *giteaconnectorv1.GiteaConnector) (*giteaconnectorv1.GiteaConnector, error)
	// UpdateGiteaConnector updates an existing Gitea connector.
	UpdateGiteaConnector(ctx context.Context, connector *giteaconnectorv1.GiteaConnector) (*giteaconnectorv1.GiteaConnector, error)
	// UpsertGiteaConnector creates or replaces a Gitea connector.
	UpsertGiteaConnector(ctx context.Context, connector *giteaconnectorv1.GiteaConnector) (*giteaconnectorv1.GiteaConnector, error)
	// DeleteGiteaConnector deletes a Gitea connector by name.
	DeleteGiteaConnector(ctx context.Context, name string) error
	// CreateGiteaAuthRequest stores a new auth request for the duration of the
	// OAuth2 flow.
	CreateGiteaAuthRequest(ctx context.Context, req *giteaconnectorv1.GiteaAuthRequest) error
	// GetGiteaAuthRequest returns a pending auth request by its state token.
	GetGiteaAuthRequest(ctx context.Context, stateToken string) (*giteaconnectorv1.GiteaAuthRequest, error)
}

// GetAllGiteaConnectors collects every Gitea connector from a paginated
// getter.
func GetAllGiteaConnectors(ctx context.Context, getter GiteaConnectorsGetter, withSecrets bool) ([]*giteaconnectorv1.GiteaConnector, error) {
	var out []*giteaconnectorv1.GiteaConnector
	var token string
	for {
		page, next, err := getter.ListGiteaConnectors(ctx, 0, token, withSecrets)
		if err != nil {
			return nil, trace.Wrap(err)
		}
		out = append(out, page...)
		if next == "" {
			return out, nil
		}
		token = next
	}
}

// ValidateGiteaConnector checks a Gitea connector for consistency and fills
// in defaults such as the resource kind, version and API endpoint URL.
func ValidateGiteaConnector(c *giteaconnectorv1.GiteaConnector) error {
	if c == nil {
		return trace.BadParameter("gitea connector is nil")
	}
	switch c.GetKind() {
	case "":
		c.SetKind(types.KindGitea)
	case types.KindGitea:
	default:
		return trace.BadParameter("gitea connector kind %q is not supported, expected %q", c.GetKind(), types.KindGitea)
	}
	switch c.GetVersion() {
	case "":
		c.SetVersion(types.V1)
	case types.V1:
	default:
		return trace.BadParameter("gitea connector version %q is not supported, expected %q", c.GetVersion(), types.V1)
	}
	if c.GetMetadata() == nil {
		return trace.BadParameter("gitea connector metadata is missing")
	}
	name := c.GetMetadata().GetName()
	if name == "" {
		return trace.BadParameter("gitea connector name is missing")
	}
	if len(name) > constants.MaxAuthConnectorNameLength {
		return trace.BadParameter("gitea connector name %q exceeds maximum length of %d bytes", name, constants.MaxAuthConnectorNameLength)
	}

	spec := c.GetSpec()
	if spec == nil {
		return trace.BadParameter("gitea connector spec is missing")
	}
	if spec.GetClientId() == "" {
		return trace.BadParameter("gitea connector %q: client_id is required", name)
	}
	if spec.GetRedirectUrl() == "" {
		return trace.BadParameter("gitea connector %q: redirect_url is required", name)
	}
	if _, err := parseGiteaURL(spec.GetRedirectUrl()); err != nil {
		return trace.BadParameter("gitea connector %q: invalid redirect_url: %v", name, err)
	}

	endpoint, err := parseGiteaURL(spec.GetEndpointUrl())
	if err != nil {
		return trace.BadParameter("gitea connector %q: invalid endpoint_url: %v", name, err)
	}
	spec.SetEndpointUrl(endpoint)

	if spec.GetApiEndpointUrl() == "" {
		spec.SetApiEndpointUrl(endpoint + GiteaAPIPathSuffix)
	} else {
		apiEndpoint, err := parseGiteaURL(spec.GetApiEndpointUrl())
		if err != nil {
			return trace.BadParameter("gitea connector %q: invalid api_endpoint_url: %v", name, err)
		}
		spec.SetApiEndpointUrl(apiEndpoint)
	}

	if len(spec.GetTeamsToRoles()) == 0 {
		return trace.BadParameter("gitea connector %q: teams_to_roles must contain at least one mapping", name)
	}
	for i, mapping := range spec.GetTeamsToRoles() {
		if mapping.GetOrganization() == "" {
			return trace.BadParameter("gitea connector %q: teams_to_roles mapping #%d is missing organization", name, i+1)
		}
		if mapping.GetTeam() == "" {
			return trace.BadParameter("gitea connector %q: teams_to_roles mapping #%d is missing team", name, i+1)
		}
		if len(mapping.GetRoles()) == 0 {
			return trace.BadParameter("gitea connector %q: teams_to_roles mapping #%d has no roles", name, i+1)
		}
	}
	return nil
}

// parseGiteaURL validates that raw is an absolute http(s) URL and returns it
// without a trailing slash.
func parseGiteaURL(raw string) (string, error) {
	if raw == "" {
		return "", trace.BadParameter("URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "", trace.Wrap(err)
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", trace.BadParameter("URL %q must use the http or https scheme", raw)
	}
	if u.Host == "" {
		return "", trace.BadParameter("URL %q is missing a host", raw)
	}
	return strings.TrimRight(raw, "/"), nil
}

// GiteaConnectorWithoutSecrets returns a copy of the connector with the
// client secret removed.
func GiteaConnectorWithoutSecrets(c *giteaconnectorv1.GiteaConnector) *giteaconnectorv1.GiteaConnector {
	if c == nil {
		return nil
	}
	out := proto.Clone(c).(*giteaconnectorv1.GiteaConnector)
	if out.GetSpec() != nil {
		out.GetSpec().SetClientSecret("")
	}
	return out
}

// GiteaClientRedirectSettings converts the connector's client redirect
// settings to the shared SSO client redirect settings type.
func GiteaClientRedirectSettings(spec *giteaconnectorv1.GiteaConnectorSpec) *types.SSOClientRedirectSettings {
	s := spec.GetClientRedirectSettings()
	if s == nil {
		return nil
	}
	return &types.SSOClientRedirectSettings{
		AllowedHttpsHostnames:     s.GetAllowedHttpsHostnames(),
		InsecureAllowedCidrRanges: s.GetInsecureAllowedCidrRanges(),
	}
}

// GiteaTeamsToRoles converts the connector's team mappings to the shared
// team-to-roles mapping type used by SSO diagnostics.
func GiteaTeamsToRoles(spec *giteaconnectorv1.GiteaConnectorSpec) []types.TeamRolesMapping {
	mappings := spec.GetTeamsToRoles()
	out := make([]types.TeamRolesMapping, 0, len(mappings))
	for _, m := range mappings {
		out = append(out, types.TeamRolesMapping{
			Organization: m.GetOrganization(),
			Team:         m.GetTeam(),
			Roles:        m.GetRoles(),
		})
	}
	return out
}

// MapGiteaClaims returns the Teleport roles granted by the connector to a
// user with the given claims. Teams are matched by exact name within their
// organization because Gitea teams have no slug.
func MapGiteaClaims(spec *giteaconnectorv1.GiteaConnectorSpec, claims types.GithubClaims) []string {
	var roles []string
	for _, mapping := range spec.GetTeamsToRoles() {
		teams, ok := claims.OrganizationToTeams[mapping.GetOrganization()]
		if !ok {
			continue
		}
		for _, team := range teams {
			if team == mapping.GetTeam() {
				roles = append(roles, mapping.GetRoles()...)
			}
		}
	}
	return utils.Deduplicate(roles)
}

// MarshalGiteaConnector marshals a Gitea connector to JSON.
func MarshalGiteaConnector(c *giteaconnectorv1.GiteaConnector, opts ...MarshalOption) ([]byte, error) {
	return MarshalProtoResource(c, opts...)
}

// UnmarshalGiteaConnector unmarshals a Gitea connector from JSON.
func UnmarshalGiteaConnector(data []byte, opts ...MarshalOption) (*giteaconnectorv1.GiteaConnector, error) {
	return UnmarshalProtoResource[*giteaconnectorv1.GiteaConnector](data, opts...)
}

// MarshalGiteaAttestationStatement serializes a hardware key attestation
// statement for storage in a Gitea auth request. A nil statement yields nil.
func MarshalGiteaAttestationStatement(att *attestationv1.AttestationStatement) ([]byte, error) {
	if att == nil {
		return nil, nil
	}
	data, err := att.Marshal()
	return data, trace.Wrap(err)
}

// UnmarshalGiteaAttestationStatement parses an attestation statement stored
// in a Gitea auth request. Empty input yields nil.
func UnmarshalGiteaAttestationStatement(data []byte) (*attestationv1.AttestationStatement, error) {
	if len(data) == 0 {
		return nil, nil
	}
	att := &attestationv1.AttestationStatement{}
	if err := att.Unmarshal(data); err != nil {
		return nil, trace.Wrap(err)
	}
	return att, nil
}
