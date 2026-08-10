spec_version = "0.7.0"

threatmodel "checkout service" {
  description = "Checkout service taking customer orders"
  author      = "@corpus"

  information_asset "order-history" {
    description                = "Customer orders, including email addresses and amounts, in the orders database"
    information_classification = "Confidential"
  }

  threat "order database exposure" {
    description = "Unauthorized access to the orders database discloses customer emails and purchase history"
    impacts     = ["Confidentiality"]
    stride      = ["Info Disclosure"]

    control "database network isolation" {
      description = "The orders database accepts connections only from the web app's subnet"
      implemented = true
    }
  }

  data_flow_diagram_v2 "checkout" {
    external_element "Customer" {}

    process "Web App" {}

    data_store "Orders Database" {
      information_asset = "order-history"
    }

    flow "https" {
      from = external_element.customer
      to   = process.web_app
    }

    flow "sql" {
      from = process.web_app
      to   = data_store.orders_database
    }
  }
}
