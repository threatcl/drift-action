spec_version = "0.7.0"

threatmodel "payments api" {
  id          = "payments.api"
  extends     = "payments"
  description = "Public HTTP API for creating and capturing payments"
  author      = "@xntrik"

  threat "duplicate capture" {
    description = "A retried capture request charges the customer twice"
    impacts     = ["Integrity"]
    stride      = ["Tampering"]

    control "idempotency keys" {
      description = "Capture requests carry an idempotency key checked in internal/api/capture.go"
      implemented = true
    }
  }

  third_party_dependency "card processor" {
    description       = "Acquiring bank API that authorises and captures card payments"
    saas              = true
    uptime_dependency = "hard"
  }
}
