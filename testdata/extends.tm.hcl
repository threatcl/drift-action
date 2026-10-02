spec_version = "0.7.0"

threatmodel "payments" {
  id          = "payments"
  description = "Payments platform shared by every payments service"
  author      = "@xntrik"

  information_asset "cardholder data" {
    description                = "Card numbers and expiry dates held by the tokenisation service"
    information_classification = "Restricted"
  }

  threat "card data exposure" {
    description = "Cardholder data leaks through logs or error responses"
    impacts     = ["Confidentiality"]
    stride      = ["Info Disclosure"]

    control "log redaction" {
      description = "Card numbers are redacted by internal/logging/redact.go before any log line is written"
      implemented = true
    }
  }
}

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
}
