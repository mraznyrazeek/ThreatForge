
import Keycloak from 'keycloak-js'

export const keycloak = new Keycloak({
  url: 'http://localhost:8080',
  realm: 'threatforge',
  clientId: 'threatforge-frontend',
})

let initializationPromise: Promise<boolean> | null = null

export function initializeKeycloak(): Promise<boolean> {
  if (!initializationPromise) {
    initializationPromise = keycloak.init({
      onLoad: 'check-sso',
      pkceMethod: 'S256',
      checkLoginIframe: false,
    })
  }

  return initializationPromise
}
