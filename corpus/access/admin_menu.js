export function adminMenu(user) {
  // deadbolt-expect DB-AUZ-001:medium
  if (user.isAdmin === true) {
    return ["refunds", "payouts"];
  }
  return [];
}
