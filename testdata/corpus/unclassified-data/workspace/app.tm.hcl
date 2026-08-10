spec_version = "0.7.0"

threatmodel "login service" {
  description = "Login service exposing POST /login and GET /profile"
  author      = "@corpus"

  information_asset "user credentials" {
    description                = "Usernames and password hashes in the users table"
    information_classification = "Restricted"
  }

  threat "session hijacking" {
    description = "A stolen session token replays against GET /profile"
    impacts     = ["Confidentiality"]
    stride      = ["Spoofing"]

    control "session validation" {
      description = "Every profile request resolves the bearer token against the session store"
      implemented = true
    }
  }
}
