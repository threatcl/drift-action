spec_version = "0.7.0"

threatmodel "storefront platform" {
  id          = "storefront"
  description = "Shared platform every storefront service runs on: customer sign-in sessions and the request middleware that guards them"
  author      = "@corpus"

  information_asset "customer sessions" {
    description                = "Session tokens issued at sign-in and carried in the sf_session cookie"
    information_classification = "Confidential"
  }

  threat "session hijacking" {
    description = "A stolen or leaked session token is replayed to act as the signed-in customer"
    impacts     = ["Confidentiality", "Integrity"]
    stride      = ["Spoofing"]

    control "idle session expiry" {
      description = "Sessions idle for more than 30 minutes are rejected and the customer must sign in again, enforced on every request in internal/session/expiry.go"
      implemented = true
    }
  }
}
