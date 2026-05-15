/**
 * Content sanitization utility to prevent XSS from untrusted scan results.
 * Uses DOMPurify to sanitize HTML content before display.
 * Security: All scan results from targets must pass through these functions.
 */
import DOMPurify from 'dompurify';

/**
 * Strip all HTML tags and attributes from content.
 * Use for rendering scan results, HTTP responses, and other untrusted data.
 */
export function sanitizeContent(html: string): string {
  return DOMPurify.sanitize(html, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
    ALLOW_DATA_ATTR: false,
  });
}

/**
 * Allow safe formatting tags only (for rich text descriptions in findings).
 * FIX: Use DOMPurify's hook system via ADD_HOOKS with proper typing.
 */
export function sanitizeRichContent(html: string): string {
  const sanitized = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'code', 'pre', 'br', 'p', 'ul', 'ol', 'li', 'a', 'span', 'div', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'blockquote'],
    ALLOWED_ATTR: ['href', 'rel', 'title', 'class'],
    ALLOW_DATA_ATTR: false,
    ADD_ATTR: ['target'],
    ADD_TAGS: ['kbd'],
  });

  // FIX: Post-process to enforce rel="noopener noreferrer" on _blank links
  // This is done after sanitization since DOMPurify's hook API isn't typed
  return sanitized.replace(
    /<a\s+([^>]*?)target="_blank"([^>]*?)>/gi,
    (match, before, after) => {
      if (!/rel=["'][^"']*noopener[^"']*["']/i.test(match) && !/rel=["'][^"']*noreferrer[^"']*["']/i.test(match)) {
        return `<a ${before}rel="noopener noreferrer" target="_blank"${after}>`;
      }
      return match;
    }
  );
}

/**
 * Check if content looks potentially malicious (XSS indicators).
 * Returns true if the content contains patterns commonly used in XSS attacks.
 */
export function isPotentiallyMalicious(content: string): boolean {
  const xssPatterns = [
    /<script[\s>]/i,
    /javascript\s*:/i,
    /on\w+\s*=/i,
    /<iframe[\s>]/i,
    /<object[\s>]/i,
    /<embed[\s>]/i,
    /<svg[\s>].*on/i,
    /eval\s*\(/i,
    /document\s*\.\s*cookie/i,
    /document\s*\.\s*write/i,
  ];
  return xssPatterns.some(pattern => pattern.test(content));
}
