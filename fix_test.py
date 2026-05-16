import re
with open("frontend/src/tests/unit/useJobMonitor.reconFailure.test.ts", "r") as f:
    content = f.read()

# Replace renderHook(() => useJobMonitor('job-1'));
# With renderHook(() => useJobMonitor('job-1'), { wrapper: ({ children }) => <ToastProvider>{children}</ToastProvider> });
# But wait, is ToastProvider imported?
