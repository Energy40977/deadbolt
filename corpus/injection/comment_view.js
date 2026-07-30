export function renderComment(node, comment) {
  // deadbolt-expect DB-INJ-005:high
  node.innerHTML = comment.body;
}
