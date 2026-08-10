spec_version = "0.7.0"

threatmodel "login service" {
  description = "Login service for the customer web app"
  author      = "@corpus"

  information_asset "user credentials" {
    description                = "Usernames and password hashes in the users table"
    information_classification = "Restricted"
  }

  threat "credential stuffing" {
    description = "Automated credential stuffing against POST /login using breached password lists"
    impacts     = ["Confidentiality"]
    stride      = ["Spoofing"]

    control "login rate limiting" {
      description = "Per-IP token-bucket rate limiting middleware on POST /login, implemented in internal/auth/ratelimit.go"
      implemented = true
    }
  }
}
