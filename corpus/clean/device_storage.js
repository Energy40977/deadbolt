// deadbolt-clean
import * as SecureStore from "expo-secure-store";

export async function persistSession(token) {
  await SecureStore.setItemAsync("auth_token", token);
}
