/**
 * API-layer shared machinery: base URL token, HTTP request interceptor
 * (prefixing relative paths with the environment base URL) and the typed
 * 404 error every API client surfaces for not-found lookups.
 */
import { HttpErrorResponse, HttpInterceptorFn } from '@angular/common/http';
import { inject, InjectionToken } from '@angular/core';
import { catchError, throwError } from 'rxjs';
import { environment } from '../../../environments/environment';

export const API_BASE_URL = new InjectionToken<string>('API_BASE_URL', {
  providedIn: 'root',
  factory: () => environment.apiUrl,
});

export class ApiNotFoundError extends Error {
  constructor(public readonly resource: string) {
    super(`Not found: ${resource}`);
    this.name = 'ApiNotFoundError';
  }
}

export function isApiNotFound(error: unknown): boolean {
  return error instanceof ApiNotFoundError;
}

export const apiBaseInterceptor: HttpInterceptorFn = (req, next) => {
  const baseUrl = inject(API_BASE_URL).replace(/\/+$/, '');
  const url = /^https?:\/\//.test(req.url) ? req.url : `${baseUrl}${req.url}`;
  return next(req.clone({ url }));
};

export const notFoundInterceptor: HttpInterceptorFn = (req, next) =>
  next(req).pipe(
    catchError((error: HttpErrorResponse) => {
      if (error.status === 404) {
        return throwError(() => new ApiNotFoundError(req.url));
      }
      return throwError(() => error);
    }),
  );
