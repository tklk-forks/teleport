# Teleport Gitea connector

variable "gitea_secret" {}

resource "teleport_gitea_connector" "gitea" {
  version = "v1"
  # This section tells Terraform that role example must be created before the Gitea connector
  depends_on = [
    teleport_role.example
  ]

  metadata = {
    name = "gitea"
    labels = {
      example = "yes"
    }
  }

  spec = {
    client_id     = "client"
    client_secret = var.gitea_secret
    redirect_url  = "https://teleport.example.com/v1/webapi/gitea/callback"
    endpoint_url  = "https://gitea.example.com"
    display       = "Gitea"

    # Gitea teams have no slug: the team name is matched exactly.
    teams_to_roles = [{
      organization = "infra"
      team         = "Owners"
      roles        = ["example"]
    }]
  }
}
