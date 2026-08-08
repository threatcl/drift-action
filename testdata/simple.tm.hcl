spec_version = "0.7.0"

threatmodel "simple" {
  description = "Minimal fixture exercising every drift-relevant block"
  author      = "@xntrik"

  information_asset "user credentials" {
    description                = "Usernames and bcrypt-hashed passwords in the users table"
    information_classification = "Restricted"
  }

  threat "credential stuffing" {
    description = "Credential stuffing against the login endpoint"
    impacts     = ["Confidentiality"]
    stride      = ["spoofing"]

    control "login rate limiting" {
      description = "Rate limiting middleware on POST /login"
      implemented = true
    }
  }

  third_party_dependency "identity provider" {
    description       = "Third-party IdP for SSO"
    saas              = true
    uptime_dependency = "degraded"
  }
}
