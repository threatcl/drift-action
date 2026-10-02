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
