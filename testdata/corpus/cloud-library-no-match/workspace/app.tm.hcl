spec_version = "0.7.0"

threatmodel "login service" {
  description = "Login service for the customer web app"
  author      = "@corpus"

  information_asset "user credentials" {
    description                = "Usernames and password hashes in the users table"
    information_classification = "Restricted"
  }

  threat "credential database theft" {
    description = "An attacker who obtains the users table cracks password hashes offline. Passwords are hashed with bcrypt at cost 12 in internal/auth/password.go, which keeps offline cracking expensive."
    impacts     = ["Confidentiality"]
    stride      = ["Info Disclosure"]

    control "password hashing" {
      description = "Server-side hashing of stored credentials in internal/auth/password.go"
      implemented = true
    }
  }
}
