// First match wins, so specific paths are registered before parameterised ones.
import { registerAuthRoutes } from './auth.js';

export function registerRoutes(router, deps) {
  registerAuthRoutes(router, deps);
}
