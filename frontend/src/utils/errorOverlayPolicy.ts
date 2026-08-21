export function shouldShowErrorStack(isDev: boolean, stack?: string): boolean {
  return Boolean(isDev && stack);
}
