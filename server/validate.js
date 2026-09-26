import { badRequest } from './http.js';

export function requireName(value, field, max = 100) {
  if (typeof value !== 'string' || value.trim() === '') throw badRequest(`${field} is required`);
  const name = value.trim();
  if (name.length > max) throw badRequest(`${field} must be at most ${max} characters`, 'too_long');
  return name;
}

export function requireEmail(value) {
  const email = typeof value === 'string' ? value.trim().toLowerCase() : '';
  const [local, domain, ...extra] = email.split('@');
  const valid = extra.length === 0 && local && domain && domain.includes('.') && !/\s/.test(email) && email.length <= 254;
  if (!valid) throw badRequest('a valid email is required', 'invalid_email');
  return email;
}

export function requirePassword(value) {
  if (typeof value !== 'string' || value.length < 8) throw badRequest('password must be at least 8 characters', 'weak_password');
  if (value.length > 200) throw badRequest('password must be at most 200 characters', 'too_long');
  return value;
}

export function requireInt(value, field, { min, max }) {
  if (!Number.isInteger(value) || value < min || value > max) {
    throw badRequest(`${field} must be a whole number from ${min} to ${max}`);
  }
  return value;
}

export const isUniqueViolation = (err) => err?.code === 'SQLITE_CONSTRAINT_UNIQUE';
export const isForeignKeyViolation = (err) => err?.code === 'SQLITE_CONSTRAINT_FOREIGNKEY';
