/**
 * Content sanitization utility to prevent XSS from untrusted scan results.
 * Uses DOMPurify to sanitize HTML content before display.
 * Security: All scan results from targets must pass through these functions.
 */
import DOMPurify from 'dompurify';

const MAX_INPUT_LENGTH = 5 * 1024 * 1024;

function validateInputLength(html: string): string {
  if (html.length > MAX_INPUT_LENGTH) {
    throw new Error(`Input too large: ${html.length} bytes exceeds ${MAX_INPUT_LENGTH} limit`);
  }
  return html;
}

export function sanitizeContent(html: string): string {
  validateInputLength(html);
  return DOMPurify.sanitize(html, {
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

export function sanitizeRichContent(html: string): string {
  validateInputLength(html);
  const sanitized = DOMPurify.sanitize(html, {
    ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'code', 'pre', 'br', 'p', 'ul', 'ol', 'li', 'span'],
    ALLOWED_ATTR: ['class'],
    ALLOW_DATA_ATTR: false,
    ADD_ATTR: [],
    ADD_TAGS: ['kbd'],
    FORBID_TAGS: ['style', 'script', 'iframe', 'object', 'embed', 'form', 'input', 'textarea', 'select', 'button'],
    FORBID_ATTR: ['onerror', 'onclick', 'onload', 'onmouseover', 'onfocus', 'onblur', 'style'],
    SANITIZE_DOM: true,
    KEEP_CONTENT: true,
    ALLOW_ARIA_ATTR: false,
  });

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
    /data\s*:\s*text\/html/i,
    /<base[\s>]/i,
    /expression\s*\(/i,
    /vbscript\s*:/i,
    /<meta[\s>].*http-equiv/i,
    /<link[\s>].*stylesheet/i,
    /url\s*\(\s*['"]?\s*javascript/i,
  ];
  return xssPatterns.some(pattern => pattern.test(content));
}
