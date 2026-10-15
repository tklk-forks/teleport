/*
Copyright 2025 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package testlib

import (
	"context"

	"github.com/gravitational/trace"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
	"github.com/stretchr/testify/require"

	giteaconnectorv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/giteaconnector/v1"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	"github.com/gravitational/teleport/api/types"
)

func (s *TerraformSuiteOSS) TestGiteaConnector() {
	ctx, cancel := context.WithCancel(context.Background())
	s.T().Cleanup(cancel)

	checkDestroyed := func(state *terraform.State) error {
		_, err := s.client.GiteaConnectorServiceClient().GetGiteaConnector(ctx, "test", false)
		if trace.IsNotFound(err) {
			return nil
		}
		return err
	}

	name := "teleport_gitea_connector.test"

	resource.Test(s.T(), resource.TestCase{
		ProtoV6ProviderFactories: s.terraformProviders,
		CheckDestroy:             checkDestroyed,
		Steps: []resource.TestStep{
			{
				Config: s.getFixture("gitea_connector_0_create.tf"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(name, "kind", "gitea"),
					resource.TestCheckResourceAttr(name, "metadata.expires", "2032-10-12T07:20:50Z"),
					resource.TestCheckResourceAttr(name, "spec.client_id", "gitea-client-id"),
					resource.TestCheckResourceAttr(name, "spec.endpoint_url", "https://gitea.example.com"),
					resource.TestCheckResourceAttr(name, "spec.api_endpoint_url", ""),
					resource.TestCheckResourceAttr(name, "spec.teams_to_roles.0.organization", "infra"),
					resource.TestCheckResourceAttr(name, "spec.teams_to_roles.0.team", "Owners"),
					resource.TestCheckResourceAttr(name, "spec.teams_to_roles.0.roles.0", "access"),
				),
			},
			{
				Config:   s.getFixture("gitea_connector_0_create.tf"),
				PlanOnly: true,
			},
			{
				Config: s.getFixture("gitea_connector_1_update.tf"),
				Check: resource.ComposeTestCheckFunc(
					resource.TestCheckResourceAttr(name, "kind", "gitea"),
					resource.TestCheckResourceAttr(name, "spec.api_endpoint_url", "https://gitea-api.example.com/api/v1"),
					resource.TestCheckResourceAttr(name, "spec.teams_to_roles.0.roles.1", "editor"),
					resource.TestCheckResourceAttr(name, "spec.teams_to_roles.1.team", "Developers"),
				),
			},
			{
				Config:   s.getFixture("gitea_connector_1_update.tf"),
				PlanOnly: true,
			},
		},
	})
}

func (s *TerraformSuiteOSS) TestImportGiteaConnector() {
	ctx, cancel := context.WithCancel(context.Background())
	s.T().Cleanup(cancel)

	r := "teleport_gitea_connector"
	id := "test_import"
	name := r + "." + id

	connector := giteaconnectorv1.GiteaConnector_builder{
		Kind:     types.KindGitea,
		Version:  types.V1,
		Metadata: headerv1.Metadata_builder{Name: id}.Build(),
		Spec: giteaconnectorv1.GiteaConnectorSpec_builder{
			ClientId:     "gitea-client-id",
			ClientSecret: "secret",
			RedirectUrl:  "https://example.com/v1/webapi/gitea/callback",
			EndpointUrl:  "https://gitea.example.com",
			TeamsToRoles: []*giteaconnectorv1.GiteaTeamRolesMapping{
				giteaconnectorv1.GiteaTeamRolesMapping_builder{
					Organization: "infra",
					Team:         "Owners",
					Roles:        []string{"access"},
				}.Build(),
			},
		}.Build(),
	}.Build()
	_, err := s.client.GiteaConnectorServiceClient().UpsertGiteaConnector(ctx, connector)
	require.NoError(s.T(), err)

	resource.Test(s.T(), resource.TestCase{
		ProtoV6ProviderFactories: s.terraformProviders,
		Steps: []resource.TestStep{
			{
				Config:        s.terraformConfig + "\n" + `resource "` + r + `" "` + id + `" { }`,
				ResourceName:  name,
				ImportState:   true,
				ImportStateId: id,
				ImportStateCheck: func(state []*terraform.InstanceState) error {
					require.Equal(s.T(), "gitea", state[0].Attributes["kind"])
					require.Equal(s.T(), "gitea-client-id", state[0].Attributes["spec.client_id"])
					require.Empty(s.T(), state[0].Attributes["spec.api_endpoint_url"])
					require.Equal(s.T(), "infra", state[0].Attributes["spec.teams_to_roles.0.organization"])
					require.Equal(s.T(), "Owners", state[0].Attributes["spec.teams_to_roles.0.team"])
					require.Equal(s.T(), "access", state[0].Attributes["spec.teams_to_roles.0.roles.0"])
					return nil
				},
			},
		},
	})
}
