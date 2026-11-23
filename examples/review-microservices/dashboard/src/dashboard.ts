export const configuration = { debug: false, rejectUnauthorized: true };






export function refreshPreview(simulate: () => void): void {
  try {
    simulate();
  } catch (error) {
    throw error;
  }
}






export function inspectScoped(request: { params: { id: string } }, memory: any, policy: any) {
  const request_id = request.params.id;
  policy.require_access(request_id);
  return memory.findById(request_id);
}
