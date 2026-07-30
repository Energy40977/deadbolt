export function trackCheckout(payload) {
  // deadbolt-expect DB-PRV-001:medium
  mixpanel.track("checkout_completed", payload);
}
