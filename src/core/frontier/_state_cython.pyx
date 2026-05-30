# cython: language_level=3
# cython: boundscheck=False
# cython: wraparound=False
# cython: nonecheck=False

import sys

def radix_sort_timestamps(list items):
    """
    Cython-optimized LSD Radix Sort for (key, timestamp) tuples.
    Accelerates Vector-Clocked CRDT state reconciliation.
    """
    cdef int n = len(items)
    if n == 0:
        return []

    cdef double min_ts = items[0][1]
    cdef double ts_val
    cdef int i
    
    # First pass: find min_ts
    for i in range(1, n):
        ts_val = <double>items[i][1]
        if ts_val < min_ts:
            min_ts = ts_val

    # Convert timestamps to unsigned 64-bit integers relative to min_ts, scaled to millisecond precision
    cdef list int_items = []
    cdef unsigned long long max_val = 0
    cdef unsigned long long val
    
    for i in range(n):
        item = items[i]
        ts_val = <double>item[1]
        val = <unsigned long long>((ts_val - min_ts) * 1000.0)
        int_items.append((item[0], ts_val, val))
        if val > max_val:
            max_val = val

    if max_val == 0:
        return [(item[0], item[1]) for item in int_items]

    # Standard LSD Radix Sort using base 256 for optimal byte-level shifting
    cdef unsigned long long placement = 1
    cdef int shift = 0
    cdef int digit
    cdef list buckets
    
    # 64-bit integer has at most 8 bytes, so at most 8 iterations for base 256
    while (max_val >> shift) > 0:
        buckets = [[] for _ in range(256)]
        for i in range(n):
            item = int_items[i]
            val = <unsigned long long>item[2]
            digit = <int>((val >> shift) & 255)
            buckets[digit].append(item)
            
        int_items = []
        for digit in range(256):
            bucket = buckets[digit]
            if len(bucket) > 0:
                int_items.extend(bucket)
        shift += 8

    # Format output
    cdef list result = []
    for i in range(n):
        item = int_items[i]
        result.append((item[0], item[1]))
    return result
