/**
 * AccessibleEmoji - Wraps emoji characters in a span with proper
 * accessibility attributes so screen readers announce them meaningfully
 * when a label is provided, or skip them when no label is given.
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
    <span role="img" aria-label={ariaLabel} aria-hidden={ariaLabel ? undefined : true}>
      {children}
    </span>
  );
}
