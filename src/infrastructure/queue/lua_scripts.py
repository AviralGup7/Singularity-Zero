"""Redis Lua scripts for atomic queue operations.

Defines Lua scripts loaded into Redis for claim, complete, fail, lease release,
and enqueue operations.

S-2 — every ownership transition (RELEASE / COMPLETE / FAIL) verifies
``job.worker_id == caller_worker_id`` before mutating state. An empty
caller id is never treated as a wildcard.
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
local caller_worker_id = ARGV[1]
local result_json = ARGV[2]
local now = ARGV[3]

if redis.call('EXISTS', job_key) == 0 then
    return {0, 'not_found'}
end

if caller_worker_id == false or caller_worker_id == nil or caller_worker_id == '' then
    return {0, 'worker_mismatch', ''}
end

local current_worker = redis.call('HGET', job_key, 'worker_id')
if current_worker ~= caller_worker_id then
    return {0, 'worker_mismatch', current_worker}
end

redis.call('HSET', job_key, 'state', 'completed', 'completed_at', now, 'result', result_json, 'lease_expires_at', '', 'worker_id', '')
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
local caller_worker_id = ARGV[1]
local error_msg = ARGV[2]
local max_retries = tonumber(ARGV[3])
local now = tonumber(ARGV[4])

if redis.call('EXISTS', job_key) == 0 then
    return {0, 'not_found'}
end

if caller_worker_id == false or caller_worker_id == nil or caller_worker_id == '' then
    return {0, 'worker_mismatch', ''}
end

local current_worker = redis.call('HGET', job_key, 'worker_id')
if current_worker ~= caller_worker_id then
    return {0, 'worker_mismatch', current_worker}
end

redis.call('SREM', worker_key, job_key)
redis.call('HSET', job_key, 'error', error_msg)

local retries = tonumber(redis.call('HGET', job_key, 'retries')) or 0
redis.call('HINCRBY', job_key, 'retries', 1)
local new_retries = retries + 1

if new_retries <= max_retries then
    local backoff = math.floor(math.min(tonumber(ARGV[5]) * math.pow(tonumber(ARGV[6]), retries), tonumber(ARGV[7])))
    local retry_at = now + backoff
    local bid_score = tonumber(redis.call('HGET', job_key, 'bid_score')) or retry_at
    redis.call('HSET', job_key, 'state', 'retrying', 'worker_id', '', 'lease_expires_at', '')
    redis.call('ZADD', queue_key, bid_score, job_key)
    redis.call('HINCRBY', metrics_key, 'retried', 1)
    return {1, 'retrying', tostring(retry_at)}
else
    redis.call('HSET', job_key, 'state', 'dead_letter', 'completed_at', tostring(now), 'worker_id', '', 'lease_expires_at', '')
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

if expected_worker_id == false or expected_worker_id == nil or expected_worker_id == '' then
    return {0, 'worker_mismatch', ''}
end

local current_worker = redis.call('HGET', job_key, 'worker_id')
if current_worker ~= expected_worker_id then
    return {0, 'worker_mismatch', current_worker}
end

local current_version = redis.call('HGET', job_key, 'lease_version')
if expected_lease_version ~= false and expected_lease_version ~= nil and expected_lease_version ~= '' and current_version ~= expected_lease_version then
    return {0, 'lease_version_mismatch', current_version}
end

redis.call('HSET', job_key, 'state', 'pending', 'worker_id', '', 'lease_expires_at', '', 'lease_version', '')
redis.call('SREM', worker_key, job_key)
local bid_score = tonumber(redis.call('HGET', job_key, 'bid_score')) or 0
redis.call('ZADD', queue_key, bid_score, job_key)
return {1, 'released'}
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
