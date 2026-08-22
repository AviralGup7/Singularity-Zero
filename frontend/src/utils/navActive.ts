/** Whether a sidebar/dock item should look current for this location. */
export function isNavPathActive(pathname: string, itemPath: string): boolean {
  const path = pathname || '/';
  const item = itemPath || '/';
  if (item === '/') return path === '/';
  return path === item || path.startsWith(`${item}/`);
}
