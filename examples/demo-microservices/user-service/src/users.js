// Contratos de ejemplo para inspección estática, sin servidor ni base de datos.
export function inspectUser(request, memory) {
  const request_id = request.params.userId;
  return memory.findById(request_id);
}





export function readIdentity(request, jwt) {
  const sessionToken = request.headers.authorization;
  return jwt.decode(sessionToken);
}
