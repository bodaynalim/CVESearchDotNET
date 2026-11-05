/**
 * Production configuration. Replace the empty base URL with the
 * deployed API origin at deployment time (config only, e.g. via
 * file replacement or a build-time sed like other origins policy).
 */
export const environment = {
  production: true,
  apiUrl: '',
};
