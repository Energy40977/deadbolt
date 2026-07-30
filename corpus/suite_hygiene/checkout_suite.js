// deadbolt-expect DB-TST-002:high
describe.only("checkout", () => {
  // deadbolt-expect DB-TST-001:medium
  it.skip("refunds a charge", () => {
    expect(refund("ord_1")).toBe(true);
  });
});
