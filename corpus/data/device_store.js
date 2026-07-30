export function persistSession(token) {
  // deadbolt-expect DB-PRV-002:high
  localStorage.setItem("auth_token", token);
}
