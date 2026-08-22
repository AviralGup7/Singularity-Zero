/**
 * Content sanitization utility to prevent XSS from untrusted scan results.
 * Uses DOMPurify to sanitize HTML content before display.
 * Security: All scan results from targets must pass through these functions.
 */
import DOMPurify from 'dompurify';

const MAX_INPUT_LENGTH = 5 * 1024 * 1024;

function validateInputLength(html: string): string {
  if (typeof html !== 'string') return '';
  if (html.length > MAX_INPUT_LENGTH) {
    throw new Error(`Input too large: ${html.length} bytes exceeds ${MAX_INPUT_LENGTH} limit`);
  }
  return html;
}

export function asSanitizableHtml(html: unknown): string {
  return typeof html === 'string' ? html : '';
}

export function sanitizeContent(html: string): string {
  const input = asSanitizableHtml(html);
  validateInputLength(input);
  return DOMPurify.sanitize(input, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
    ALLOW_DATA_ATTR: false,
    RETURN_DOM: false,
    RETURN_DOM_FRAGMENT: false,
    RETURN_TRUSTED_TYPE: false,
    FORCE_BODY: true,
    SANITIZE_DOM: true,
    KEEP_CONTENT: true,
  });
}


