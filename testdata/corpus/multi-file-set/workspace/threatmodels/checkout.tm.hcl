spec_version = "0.7.0"

threatmodel "checkout service" {
  id          = "storefront.checkout"
  extends     = "storefront"
  description = "Checkout service: turns a signed-in customer's cart into a paid order"
  author      = "@corpus"

  information_asset "order history" {
    description                = "Past orders with delivery addresses and the last four digits of the card used"
    information_classification = "Confidential"
  }

  threat "order tampering" {
    description = "A customer alters item prices or quantities between cart and payment"
    impacts     = ["Integrity"]
    stride      = ["Tampering"]

    control "server-side pricing" {
      description = "Order totals are recomputed from the catalogue on the server, and prices submitted by the client are ignored"
      implemented = true
    }
  }
}
