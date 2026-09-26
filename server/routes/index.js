// First match wins, so specific paths are registered before parameterised ones.
import { registerAuthRoutes } from './auth.js';
import { registerOrgRoutes } from './orgs.js';
import { registerInviteRoutes } from './invites.js';

export function registerRoutes(router, deps) {
  registerAuthRoutes(router, deps);
  registerOrgRoutes(router, deps);
  registerInviteRoutes(router, deps);
}
