spec_version = "0.7.0"

threatmodel "login service" {
  description = "Login service for the customer web app"
  author      = "@corpus"

  information_asset "session tokens" {
    description                = "Bearer tokens proving a signed-in session"
    information_classification = "Restricted"
  }

  threat "session token theft" {
    description = "A stolen bearer token grants the attacker the victim's session"
    impacts     = ["Confidentiality"]
    stride      = ["Spoofing"]

    control "short session lifetime" {
      description = "Session tokens expire after 24 hours"
      implemented = true
    }
  }

  third_party_dependency "identity provider" {
    description       = "Hosted IdP handling SSO log-ins"
    saas              = true
    uptime_dependency = "degraded"
  }
}
