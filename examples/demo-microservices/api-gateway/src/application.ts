// Muestra estática de configuración. No arranca un servidor.
export const gatewaySettings = {
  headers: { cacheControl: "private" },
  debug: true,
};






export function refreshPreview(simulate: () => void): void {
  try {
    simulate();
  } catch (error) {
  }
}
