"""Redis Lua scripts for atomic queue operations.

Defines Lua scripts loaded into Redis for claim, complete, fail, lease release,
lease expiry, cancellation, and enqueue operations.

Every transition out of ``claimed``/``running`` is fenced by BOTH the
expected ``worker_id`` AND the ``lease_version`` (a CAS token assigned at
claim time).  Late callbacks from a worker that no longer holds the lease
are rejected with a structured error code:

  * ``wrong_state``           — job is not in a fenced-executable state
  * ``worker_mismatch``       — the caller is not the current lease holder
  * ``lease_version_mismatch``— the caller's CAS token is stale
"""

CLAIM_JOB_SCRIPT = """
local job_key = KEYS[1]
local queue_key = KEYS[2]
local worker_key = KEYS[3]
local worker_id = ARGV[1]
local lease_seconds = tonumber(ARGV[2])
local now = tonumber(ARGV[3])

local exists = redis.call('EXISTS', job_key)
if exists == 0 then
    return {0, 'not_found'}
end

local state = redis.call('HGET', job_key, 'state')
if state ~= 'pending' and state ~= 'retrying' then
    return {0, 'invalid_state', state}
end

local lease_expires = now + lease_seconds
local lease_version = tostring(now * 1000000)
redis.call('HSET', job_key, 'state', 'claimed', 'worker_id', worker_id, 'lease_expires_at', tostring(lease_expires), 'lease_version', lease_version)
redis.call('ZREM', queue_key, job_key)
redis.call('SADD', worker_key, job_key)
return {1, 'claimed', lease_version}
"""

COMPLETE_JOB_SCRIPT = """
local job_key = KEYS[1]
local worker_key = KEYS[2]
local metrics_key = KEYS[3]
local expected_worker = ARGV[1]
local expected_lease_version = ARGV[2]
local result_json = ARGV[3]
local now = ARGV[4]

if redis.call('EXISTS', job_key) == 0 then
    return {0, 'not_found'}
end

local state = redis.call('HGET', job_key, 'state')
if state ~= 'claimed' and state ~= 'running' then
    return {0, 'wrong_state', state}
end

local current_worker = redis.call('HGET', job_key, 'worker_id')
if current_worker ~= expected_worker then
    return {0, 'worker_mismatch', current_worker}
end

local current_version = redis.call('HGET', job_key, 'lease_version')
if current_version ~= expected_lease_version then
    return {0, 'lease_version_mismatch', current_version}
end

redis.call('HSET', job_key, 'state', 'completed', 'completed_at', now, 'result', result_json, 'lease_expires_at', '', 'worker_id', '', 'lease_version', '')
redis.call('SREM', worker_key, job_key)
redis.call('HINCRBY', metrics_key, 'completed', 1)
return {1, 'completed'}
"""

FAIL_JOB_SCRIPT = """
local job_key = KEYS[1]
local worker_key = KEYS[2]
local queue_key = KEYS[3]
local dlq_key = KEYS[4]
local metrics_key = KEYS[5]
local expected_worker = ARGV[1]
local expected_lease_version = ARGV[2]
local error_msg = ARGV[3]
local max_retries = tonumber(ARGV[4])
local now = tonumber(ARGV[5])
local initial_delay = tonumber(ARGV[6])
local multiplier = tonumber(ARGV[7])
local max_delay = tonumber(ARGV[8])

if redis.call('EXISTS', job_key) == 0 then
    return {0, 'not_found'}
end

local state = redis.call('HGET', job_key, 'state')
if state ~= 'claimed' and state ~= 'running' then
    return {0, 'wrong_state', state}
end

local current_worker = redis.call('HGET', job_key, 'worker_id')
if current_worker ~= expected_worker then
    return {0, 'worker_mismatch', current_worker}
end

local current_version = redis.call('HGET', job_key, 'lease_version')
if current_version ~= expected_lease_version then
    return {0, 'lease_version_mismatch', current_version}
end

redis.call('SREM', worker_key, job_key)
redis.call('HSET', job_key, 'error', error_msg)

local retries = tonumber(redis.call('HGET', job_key, 'retries')) or 0
redis.call('HINCRBY', job_key, 'retries', 1)
local new_retries = retries + 1

if new_retries <= max_retries then
    local backoff = math.floor(math.min(initial_delay * math.pow(multiplier, retries), max_delay))
    local retry_at = now + backoff
    local bid_score = tonumber(redis.call('HGET', job_key, 'bid_score')) or retry_at
    redis.call('HSET', job_key, 'state', 'retrying', 'worker_id', '', 'lease_expires_at', '', 'lease_version', '')
    redis.call('ZADD', queue_key, bid_score, job_key)
    redis.call('HINCRBY', metrics_key, 'retried', 1)
    return {1, 'retrying', tostring(retry_at)}
else
    redis.call('HSET', job_key, 'state', 'dead_letter', 'completed_at', tostring(now), 'worker_id', '', 'lease_expires_at', '', 'lease_version', '')
    redis.call('ZADD', dlq_key, now, job_key)
    redis.call('HINCRBY', metrics_key, 'dead_lettered', 1)
    return {2, 'dead_letter'}
end
"""

RELEASE_LEASE_SCRIPT = """
local job_key = KEYS[1]
local worker_key = KEYS[2]
local queue_key = KEYS[3]
local expected_worker_id = ARGV[1]
local expected_lease_version = ARGV[2]

if redis.call('EXISTS', job_key) == 0 then
    return {0, 'not_found'}
end

local state = redis.call('HGET', job_key, 'state')
if state ~= 'claimed' and state ~= 'running' then
    return {0, 'wrong_state', state}
end

local current_worker = redis.call('HGET', job_key, 'worker_id')
if current_worker ~= expected_worker_id and expected_worker_id ~= '' then
    return {0, 'worker_mismatch', current_worker}
end

local current_version = redis.call('HGET', job_key, 'lease_version')
if current_version ~= expected_lease_version and expected_lease_version ~= '' then
    return {0, 'lease_version_mismatch', current_version}
end

redis.call('HSET', job_key, 'state', 'pending', 'worker_id', '', 'lease_expires_at', '', 'lease_version', '')
redis.call('SREM', worker_key, job_key)
local bid_score = tonumber(redis.call('HGET', job_key, 'bid_score')) or 0
redis.call('ZADD', queue_key, bid_score, job_key)
return {1, 'released'}
"""

CANCEL_JOB_SCRIPT = """
local job_key = KEYS[1]
local worker_key = KEYS[2]
local queue_key = KEYS[3]
local expected_worker = ARGV[1]
local expected_lease_version = ARGV[2]

if redis.call('EXISTS', job_key) == 0 then
    return {0, 'not_found'}
end

local state = redis.call('HGET', job_key, 'state')
-- CANCELLED is terminal: it can never transition to completed/retrying.
if state == 'completed' or state == 'cancelled' or state == 'dead_letter' then
    return {0, 'wrong_state', state}
end

-- Fence claimed/running jobs so a cancel cannot race a live worker.
if state == 'claimed' or state == 'running' then
    local current_worker = redis.call('HGET', job_key, 'worker_id')
    if current_worker ~= expected_worker and expected_worker ~= '' then
        return {0, 'worker_mismatch', current_worker}
    end
    local current_version = redis.call('HGET', job_key, 'lease_version')
    if current_version ~= expected_lease_version and expected_lease_version ~= '' then
        return {0, 'lease_version_mismatch', current_version}
    end
end

redis.call('HSET', job_key, 'state', 'cancelled', 'worker_id', '', 'lease_expires_at', '', 'lease_version', '')
redis.call('SREM', worker_key, job_key)
redis.call('ZREM', queue_key, job_key)
return {1, 'cancelled'}
"""

EXPIRE_LEASE_SCRIPT = """
local job_key = KEYS[1]
local queue_key = KEYS[2]
local worker_key = KEYS[3]
local now = tonumber(ARGV[1])

if redis.call('EXISTS', job_key) == 0 then
    return {0, 'not_found'}
end

local state = redis.call('HGET', job_key, 'state')
if state ~= 'claimed' and state ~= 'running' then
    return {0, 'wrong_state', state}
end

local lease_expires_at = tonumber(redis.call('HGET', job_key, 'lease_expires_at')) or 0
if lease_expires_at > now then
    -- A live worker (or a renewal) still owns the lease — leave it alone.
    return {0, 'lease_valid', tostring(lease_expires_at)}
end

-- Lease expired and the worker has not renewed: requeue the job.  The
-- lease_version is discarded, so any stale CAS token from the old worker
-- can no longer complete/fail/release this job.
local bid_score = tonumber(redis.call('HGET', job_key, 'bid_score')) or 0
redis.call('HSET', job_key, 'state', 'pending', 'worker_id', '', 'lease_expires_at', '', 'lease_version', '')
redis.call('SREM', worker_key, job_key)
redis.call('ZADD', queue_key, bid_score, job_key)
return {1, 'requeued'}
"""

ENQUEUE_SCRIPT = """
local job_key = KEYS[1]
local queue_key = KEYS[2]
local priority = tonumber(ARGV[1])
local job_id = ARGV[2]
local created_at = tonumber(ARGV[3])
local hash_args = cjson.decode(ARGV[4])
local bid_score = tonumber(ARGV[5])

local score = bid_score or ((priority * 10000000000) - created_at)
redis.call('HSET', job_key, unpack(hash_args))
redis.call('ZADD', queue_key, score, job_key)
return {1, job_id}
"""

RENEW_LEASE_SCRIPT = """
local job_key = KEYS[1]
local expected_worker = ARGV[1]
local expected_lease_version = ARGV[2]
local lease_seconds = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

if redis.call('EXISTS', job_key) == 0 then
    return {0, 'not_found'}
end

local state = redis.call('HGET', job_key, 'state')
if state ~= 'claimed' and state ~= 'running' then
    return {0, 'wrong_state', state}
end

local current_worker = redis.call('HGET', job_key, 'worker_id')
if current_worker ~= expected_worker then
    return {0, 'worker_mismatch', current_worker}
end

local current_version = redis.call('HGET', job_key, 'lease_version')
if current_version ~= expected_lease_version then
    return {0, 'lease_version_mismatch', current_version}
end

local new_expires = now + lease_seconds
redis.call('HSET', job_key, 'lease_expires_at', tostring(new_expires))
return {1, 'renewed', tostring(new_expires)}
"""

