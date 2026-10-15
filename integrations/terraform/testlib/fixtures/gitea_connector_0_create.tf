resource "teleport_gitea_connector" "test" {
  version = "v1"
  metadata = {
    name    = "test"
    expires = "2032-10-12T07:20:50Z"
    labels = {
      example = "yes"
    }
  }

  spec = {
    client_id     = "gitea-client-id"
    client_secret = "gitea-client-secret"
    redirect_url  = "https://example.com/v1/webapi/gitea/callback"
    endpoint_url  = "https://gitea.example.com"
    display       = "Gitea"

    teams_to_roles = [{
      organization = "infra"
      team         = "Owners"
      roles        = ["access"]
    }]
  }
}
