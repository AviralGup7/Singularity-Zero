/**
 * AccessibleEmoji - Wraps emoji characters in a span with proper
 * accessibility attributes so screen readers skip them.
 *
 * Usage: <AccessibleEmoji ariaLabel="Dark mode">🌙</AccessibleEmoji>
 */
export function AccessibleEmoji({
  children,
  ariaLabel,
}: {
  children: string;
  ariaLabel?: string;
}) {
  return (
    <span role="img" aria-label={ariaLabel} aria-hidden="true">
      {children}
    </span>
  );
}
