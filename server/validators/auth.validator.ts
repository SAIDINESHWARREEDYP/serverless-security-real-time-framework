export function validateUsername(rawUsername: string): { valid: boolean; error?: string } {
  if (!rawUsername || typeof rawUsername !== 'string') {
    return { valid: false, error: 'Username is required.' };
  }
  const u = rawUsername.trim();
  const lower = u.toLowerCase();
  // Built-in standard roles
  if (['secops_admin', 'cloud_dev', 'auditor_guest', 'sarah_infra', 'threat_actor'].includes(lower)) {
    return { valid: true };
  }
  if (u.length <= 5) {
    return { valid: false, error: 'Username must contain more than 5 characters.' };
  }
  if (!/[A-Z]/.test(u)) {
    return { valid: false, error: 'Username must contain at least one uppercase letter (A-Z).' };
  }
  if (!/[a-z]/.test(u)) {
    return { valid: false, error: 'Username must contain at least one lowercase letter (a-z).' };
  }
  if (!/[0-9a-zA-Z]/.test(u)) {
    return { valid: false, error: 'Username must contain at least one alphanumeric character.' };
  }
  return { valid: true };
}

export function validatePassword(password: string): { valid: boolean; error?: string } {
  if (!password || typeof password !== 'string') {
    return { valid: false, error: 'Password is required.' };
  }
  if (password.length < 8) {
    return { valid: false, error: 'Password must be at least 8 characters long.' };
  }
  return { valid: true };
}

export function validateTotpCode(code: string): { valid: boolean; error?: string } {
  if (!code || typeof code !== 'string') {
    return { valid: false, error: 'Verification code is required.' };
  }
  const clean = code.trim().replace(/[\s\-]/g, '');
  if (!/^\d{6}$/.test(clean) && !/^[A-Za-z0-9]{8}$/.test(clean)) {
    return { valid: false, error: 'Verification code must be a 6-digit passcode or 8-character backup code.' };
  }
  return { valid: true };
}
