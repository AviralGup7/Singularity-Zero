#!/usr/bin/env bash
# =============================================================================
# Cyber Security Test Pipeline - Backup Script
# =============================================================================
# Backs up Redis data, SQLite databases, and output data to timestamped
# backup archives. Supports local and remote destinations.
# =============================================================================

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/configs/backup-config.json"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
BACKUP_DIR="$PROJECT_ROOT/backups"
LOG_FILE="$PROJECT_ROOT/logs/backup_${TIMESTAMP}.log"

# ── Colors for output ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ── Logging ────────────────────────────────────────────────────────────────
log() {
    local level="$1"
    shift
    local msg="$*"
    local ts
    ts="$(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${ts} [${level}] ${msg}" | tee -a "$LOG_FILE"
}

log_info()    { log "INFO"    "$@"; }
log_warn()    { log "WARN"    "${YELLOW}$*${NC}"; }
log_error()   { log "ERROR"   "${RED}$*${NC}"; }
log_success() { log "SUCCESS" "${GREEN}$*${NC}"; }

# ── Read configuration ────────────────────────────────────────────────────
read_config() {
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log_warn "Config file not found at $CONFIG_FILE, using defaults"
        RETENTION_DAYS=30
        COMPRESS=true
        COMPRESSION_LEVEL=6
        BACKUP_REDIS=true
        BACKUP_SQLITE=true
        BACKUP_OUTPUT=true
        BACKUP_LOGS=true
        BACKUP_CONFIGS=true
        REDIS_HOST="${REDIS_HOST:-localhost}"
        REDIS_PORT="${REDIS_PORT:-6379}"
        REDIS_PASSWORD=""
        SQLITE_PATHS=("$PROJECT_ROOT/data/pipeline.db")
        OUTPUT_PATHS=("$PROJECT_ROOT/output")
        LOG_PATHS=("$PROJECT_ROOT/logs")
        CONFIG_PATHS=("$PROJECT_ROOT/configs" "$PROJECT_ROOT/.env")
        DESTINATION="$BACKUP_DIR"
        REMOTE_DEST=""
        VERIFY_BACKUP=true
        ENCRYPT=false
        return
    fi

    if command -v jq &>/dev/null; then
        RETENTION_DAYS=$(jq -r '.backup.retention_days // 30' "$CONFIG_FILE")
        COMPRESS=$(jq -r '.backup.compress // true' "$CONFIG_FILE")
        COMPRESSION_LEVEL=$(jq -r '.backup.compression_level // 6' "$CONFIG_FILE")
        BACKUP_REDIS=$(jq -r '.backup.components.redis // true' "$CONFIG_FILE")
        BACKUP_SQLITE=$(jq -r '.backup.components.sqlite // true' "$CONFIG_FILE")
        BACKUP_OUTPUT=$(jq -r '.backup.components.output // true' "$CONFIG_FILE")
        BACKUP_LOGS=$(jq -r '.backup.components.logs // true' "$CONFIG_FILE")
        BACKUP_CONFIGS=$(jq -r '.backup.components.configs // true' "$CONFIG_FILE")
        REDIS_HOST=$(jq -r '.backup.redis.host // "localhost"' "$CONFIG_FILE")
        REDIS_PORT=$(jq -r '.backup.redis.port // 6379' "$CONFIG_FILE")
        REDIS_PASSWORD=$(jq -r '.backup.redis.password // ""' "$CONFIG_FILE")
        DESTINATION=$(jq -r '.backup.destination.local_path // "'"$BACKUP_DIR"'"' "$CONFIG_FILE")
        REMOTE_DEST=$(jq -r '.backup.destination.remote_path // ""' "$CONFIG_FILE")
        VERIFY_BACKUP=$(jq -r '.backup.verify_backup // true' "$CONFIG_FILE")
        ENCRYPT=$(jq -r '.backup.encrypt // false' "$CONFIG_FILE")

        # Read arrays
        mapfile -t SQLITE_PATHS < <(jq -r '.backup.components.sqlite_paths[]? // empty' "$CONFIG_FILE")
        mapfile -t OUTPUT_PATHS < <(jq -r '.backup.components.output_paths[]? // empty' "$CONFIG_FILE")
        mapfile -t LOG_PATHS < <(jq -r '.backup.components.log_paths[]? // empty' "$CONFIG_FILE")
        mapfile -t CONFIG_PATHS < <(jq -r '.backup.components.config_paths[]? // empty' "$CONFIG_FILE")
    else
        log_warn "jq not installed, using defaults"
        RETENTION_DAYS=30
        COMPRESS=true
        COMPRESSION_LEVEL=6
        BACKUP_REDIS=true
        BACKUP_SQLITE=true
        BACKUP_OUTPUT=true
        BACKUP_LOGS=true
        BACKUP_CONFIGS=true
        REDIS_HOST="${REDIS_HOST:-localhost}"
        REDIS_PORT="${REDIS_PORT:-6379}"
        REDIS_PASSWORD=""
        SQLITE_PATHS=("$PROJECT_ROOT/data/pipeline.db")
        OUTPUT_PATHS=("$PROJECT_ROOT/output")
        LOG_PATHS=("$PROJECT_ROOT/logs")
        CONFIG_PATHS=("$PROJECT_ROOT/configs" "$PROJECT_ROOT/.env")
        DESTINATION="$BACKUP_DIR"
        REMOTE_DEST=""
        VERIFY_BACKUP=true
        ENCRYPT=false
    fi

    # Default paths if arrays are empty
    [[ ${#SQLITE_PATHS[@]} -eq 0 ]] && SQLITE_PATHS=("$PROJECT_ROOT/data/pipeline.db")
    [[ ${#OUTPUT_PATHS[@]} -eq 0 ]] && OUTPUT_PATHS=("$PROJECT_ROOT/output")
    [[ ${#LOG_PATHS[@]} -eq 0 ]] && LOG_PATHS=("$PROJECT_ROOT/logs")
    [[ ${#CONFIG_PATHS[@]} -eq 0 ]] && CONFIG_PATHS=("$PROJECT_ROOT/configs")
}

# ── Pre-flight checks ─────────────────────────────────────────────────────
preflight() {
    log_info "Running pre-flight checks..."

    # Create necessary directories
    mkdir -p "$BACKUP_DIR" "$DESTINATION" "$(dirname "$LOG_FILE")"

    # Check required tools
    local required_tools=("tar")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            log_error "Required tool '$tool' not found"
            exit 1
        fi
    done

    # Check Redis if backing up
    if [[ "$BACKUP_REDIS" == "true" ]]; then
        if command -v redis-cli &>/dev/null; then
            local redis_cmd="redis-cli -h $REDIS_HOST -p $REDIS_PORT"
            [[ -n "$REDIS_PASSWORD" ]] && redis_cmd="$redis_cmd -a $REDIS_PASSWORD"
            if ! $redis_cmd ping &>/dev/null 2>&1; then
                log_warn "Redis is not responding at $REDIS_HOST:$REDIS_PORT"
            fi
        else
            log_warn "redis-cli not found, Redis backup will use volume copy"
        fi
    fi

    log_success "Pre-flight checks passed"
}

# ── Backup Redis ──────────────────────────────────────────────────────────
backup_redis() {
    local backup_stage="$1"

    log_info "Starting Redis backup..."

    local redis_dump_dir="$backup_stage/redis"
    mkdir -p "$redis_dump_dir"

    # Method 1: Use BGSAVE and copy dump file
    if command -v redis-cli &>/dev/null; then
        local redis_cmd="redis-cli -h $REDIS_HOST -p $REDIS_PORT"
        [[ -n "$REDIS_PASSWORD" ]] && redis_cmd="$redis_cmd -a $REDIS_PASSWORD"

        # Trigger background save
        log_info "Triggering Redis BGSAVE..."
        if $redis_cmd BGSAVE 2>/dev/null | grep -q "OK\|Background saving"; then
            log_info "BGSAVE initiated, waiting for completion..."
            # Wait for background save to finish
            local max_wait=60
            local waited=0
            while [[ $waited -lt $max_wait ]]; do
                local status
                status=$($redis_cmd LASTSAVE 2>/dev/null || echo "0")
                if [[ -n "$status" ]]; then
                    break
                fi
                sleep 2
                waited=$((waited + 2))
            done
            sleep 5 # Additional wait for dump to complete
        fi

        # Try to find and copy the dump file
        local dump_path
        dump_path=$($redis_cmd CONFIG GET dir 2>/dev/null | tail -1 || echo "")
        local dump_file
        dump_file=$($redis_cmd CONFIG GET dbfilename 2>/dev/null | tail -1 || echo "dump.rdb")

        if [[ -n "$dump_path" && -f "$dump_path/$dump_file" ]]; then
            cp "$dump_path/$dump_file" "$redis_dump_dir/dump.rdb"
            log_info "Redis dump copied from $dump_path/$dump_file"
        fi

        # Export all databases as RDB
        log_info "Creating Redis info snapshot..."
        $redis_cmd INFO > "$redis_dump_dir/redis_info.txt" 2>/dev/null || true
    fi

    # Method 2: Copy Docker volume if available
    if docker volume ls --format '{{.Name}}' 2>/dev/null | grep -q "redis"; then
        log_info "Backing up Redis Docker volume..."
        docker run --rm \
            -v "$(docker volume ls --format '{{.Name}}' | grep redis | head -1):/redis-data" \
            -v "$redis_dump_dir:/backup" \
            alpine tar czf /backup/redis-volume.tar.gz -C /redis-data . 2>/dev/null || true
        log_info "Redis Docker volume backed up"
    fi

    log_success "Redis backup completed"
}

# ── Backup SQLite ─────────────────────────────────────────────────────────
backup_sqlite() {
    local backup_stage="$1"

    log_info "Starting SQLite backup..."

    local sqlite_dir="$backup_stage/sqlite"
    mkdir -p "$sqlite_dir"

    for db_path in "${SQLITE_PATHS[@]}"; do
        if [[ ! -f "$db_path" ]]; then
            log_warn "SQLite database not found: $db_path"
            continue
        fi

        local db_name
        db_name="$(basename "$db_path")"
        local db_dir
        db_dir="$(dirname "$db_path")"

        # Use SQLite online backup if available
        if command -v sqlite3 &>/dev/null; then
            log_info "Creating SQLite backup of $db_name using .backup..."
            sqlite3 "$db_path" ".backup '$sqlite_dir/${db_name%.db}_backup_${TIMESTAMP}.db'" 2>/dev/null || {
                log_warn "SQLite .backup failed, falling back to file copy"
                cp "$db_path" "$sqlite_dir/$db_name"
            }
        else
            # Fallback: copy the file (may be inconsistent if database is in use)
            log_warn "sqlite3 not found, using file copy (may be inconsistent)"
            cp "$db_path" "$sqlite_dir/$db_name"
        fi

        # Also backup WAL and SHM files if they exist
        [[ -f "${db_path}-wal" ]] && cp "${db_path}-wal" "$sqlite_dir/${db_name}-wal"
        [[ -f "${db_path}-shm" ]] && cp "${db_path}-shm" "$sqlite_dir/${db_name}-shm"

        log_info "Backed up: $db_path"
    done

    # Backup Alembic migrations
    if [[ -d "$PROJECT_ROOT/alembic" ]]; then
        log_info "Backing up Alembic migrations..."
        cp -r "$PROJECT_ROOT/alembic" "$sqlite_dir/alembic" 2>/dev/null || true
    fi

    log_success "SQLite backup completed"
}

# ── Backup Output Data ────────────────────────────────────────────────────
backup_output() {
    local backup_stage="$1"

    log_info "Starting output data backup..."

    local output_dir="$backup_stage/output"
    mkdir -p "$output_dir"

    for path in "${OUTPUT_PATHS[@]}"; do
        if [[ ! -e "$path" ]]; then
            log_warn "Output path not found: $path"
            continue
        fi

        local name
        name="$(basename "$path")"
        cp -r "$path" "$output_dir/$name"
        log_info "Backed up output: $path"
    done

    log_success "Output data backup completed"
}

# ── Backup Logs ───────────────────────────────────────────────────────────
backup_logs() {
    local backup_stage="$1"

    log_info "Starting logs backup..."

    local logs_dir="$backup_stage/logs"
    mkdir -p "$logs_dir"

    for path in "${LOG_PATHS[@]}"; do
        if [[ ! -e "$path" ]]; then
            log_warn "Log path not found: $path"
            continue
        fi

        local name
        name="$(basename "$path")"
        # Don't backup the current backup log
        if [[ "$path" != "$(dirname "$LOG_FILE")" ]]; then
            cp -r "$path" "$logs_dir/$name" 2>/dev/null || true
            log_info "Backed up logs: $path"
        fi
    done

    log_success "Logs backup completed"
}

# ── Backup Configs ────────────────────────────────────────────────────────
backup_configs() {
    local backup_stage="$1"

    log_info "Starting configuration backup..."

    local config_dir="$backup_stage/configs"
    mkdir -p "$config_dir"

    for path in "${CONFIG_PATHS[@]}"; do
        if [[ ! -e "$path" ]]; then
            log_warn "Config path not found: $path"
            continue
        fi

        local name
        name="$(basename "$path")"
        if [[ -f "$path" ]]; then
            cp "$path" "$config_dir/$name"
        else
            cp -r "$path" "$config_dir/$name"
        fi
        log_info "Backed up config: $path"
    done

    # Backup environment file (exclude secrets from logs)
    if [[ -f "$PROJECT_ROOT/.env" ]]; then
        cp "$PROJECT_ROOT/.env" "$config_dir/.env"
        chmod 600 "$config_dir/.env"
        log_info "Backed up .env (permissions set to 600)"
    fi

    log_success "Configuration backup completed"
}

# ── Create Archive ────────────────────────────────────────────────────────
create_archive() {
    local backup_stage="$1"
    local archive_name="backup_${TIMESTAMP}"
    local archive_path="$DESTINATION/$archive_name"

    log_info "Creating backup archive..."

    if [[ "$COMPRESS" == "true" ]]; then
        archive_path="${archive_path}.tar.gz"
        tar -czf "$archive_path" \
            -C "$PROJECT_ROOT" \
            --exclude='__pycache__' \
            --exclude='*.pyc' \
            --exclude='.venv' \
            --exclude='.venv312' \
            --exclude='.venv314' \
            --exclude='node_modules' \
            --exclude='.mypy_cache' \
            --exclude='.ruff_cache' \
            "$(basename "$backup_stage")" 2>/dev/null
        log_info "Compressed archive created: $archive_path"
    else
        archive_path="${archive_path}.tar"
        tar -cf "$archive_path" \
            -C "$PROJECT_ROOT" \
            "$(basename "$backup_stage")" 2>/dev/null
        log_info "Archive created: $archive_path"
    fi

    # Generate checksum
    if command -v sha256sum &>/dev/null; then
        sha256sum "$archive_path" > "${archive_path}.sha256"
        log_info "SHA256 checksum generated"
    elif command -v shasum &>/dev/null; then
        shasum -a 256 "$archive_path" > "${archive_path}.sha256"
        log_info "SHA256 checksum generated"
    fi

    # Create backup manifest
    cat > "${archive_path}.manifest.json" << EOF
{
    "backup_id": "${TIMESTAMP}",
    "created_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
    "archive": "$(basename "$archive_path")",
    "components": {
        "redis": $BACKUP_REDIS,
        "sqlite": $BACKUP_SQLITE,
        "output": $BACKUP_OUTPUT,
        "logs": $BACKUP_LOGS,
        "configs": $BACKUP_CONFIGS
    },
    "size_bytes": $(stat -f%z "$archive_path" 2>/dev/null || stat -c%s "$archive_path" 2>/dev/null || echo 0),
    "hostname": "$(hostname)",
    "project_root": "$PROJECT_ROOT"
}
EOF
    log_info "Backup manifest created"

    echo "$archive_path"
}

# ── Verify Backup ─────────────────────────────────────────────────────────
verify_backup() {
    local archive_path="$1"

    if [[ "$VERIFY_BACKUP" != "true" ]]; then
        return 0
    fi

    log_info "Verifying backup integrity..."

    # Verify archive is valid
    if ! tar -tzf "$archive_path" &>/dev/null && ! tar -tf "$archive_path" &>/dev/null; then
        log_error "Backup archive is corrupted!"
        return 1
    fi

    # Verify checksum if available
    if [[ -f "${archive_path}.sha256" ]]; then
        if command -v sha256sum &>/dev/null; then
            if sha256sum -c "${archive_path}.sha256" &>/dev/null; then
                log_info "Checksum verification passed"
            else
                log_error "Checksum verification failed!"
                return 1
            fi
        fi
    fi

    log_success "Backup verification passed"
}

# ── Upload to Remote ──────────────────────────────────────────────────────
upload_remote() {
    local archive_path="$1"

    if [[ -z "$REMOTE_DEST" ]]; then
        return 0
    fi

    log_info "Uploading backup to remote destination..."

    if [[ "$REMOTE_DEST" == s3://* ]]; then
        if command -v aws &>/dev/null; then
            aws s3 cp "$archive_path" "$REMOTE_DEST/"
            [[ -f "${archive_path}.sha256" ]] && aws s3 cp "${archive_path}.sha256" "$REMOTE_DEST/"
            [[ -f "${archive_path}.manifest.json" ]] && aws s3 cp "${archive_path}.manifest.json" "$REMOTE_DEST/"
        else
            log_error "aws CLI not found, cannot upload to S3"
            return 1
        fi
    elif [[ "$REMOTE_DEST" == gs://* ]]; then
        if command -v gsutil &>/dev/null; then
            gsutil cp "$archive_path" "$REMOTE_DEST/"
        else
            log_error "gsutil not found, cannot upload to GCS"
            return 1
        fi
    elif [[ "$REMOTE_DEST" == *:* ]]; then
        # SCP destination (user@host:/path)
        scp "$archive_path" "$REMOTE_DEST/"
        [[ -f "${archive_path}.sha256" ]] && scp "${archive_path}.sha256" "$REMOTE_DEST/"
        [[ -f "${archive_path}.manifest.json" ]] && scp "${archive_path}.manifest.json" "$REMOTE_DEST/"
    fi

    log_success "Remote upload completed"
}

# ── Cleanup Old Backups ───────────────────────────────────────────────────
cleanup_old_backups() {
    log_info "Cleaning up backups older than $RETENTION_DAYS days..."

    find "$DESTINATION" -name "backup_*.tar*" -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true
    find "$DESTINATION" -name "backup_*.sha256" -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true
    find "$DESTINATION" -name "backup_*.manifest.json" -mtime +"$RETENTION_DAYS" -delete 2>/dev/null || true

    log_info "Cleanup completed"
}

# ── Cleanup Stage Directory ───────────────────────────────────────────────
cleanup_stage() {
    local backup_stage="$1"
    rm -rf "$backup_stage"
}

# ── Main ──────────────────────────────────────────────────────────────────
main() {
    local start_time
    start_time=$(date +%s)

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║       Cyber Security Test Pipeline - Backup             ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    log_info "Starting backup at $(date)"
    log_info "Project root: $PROJECT_ROOT"

    # Read configuration
    read_config

    # Pre-flight checks
    preflight

    # Create staging directory
    local backup_stage="$PROJECT_ROOT/.backup_staging/backup_${TIMESTAMP}"
    mkdir -p "$backup_stage"

    # Execute backups
    [[ "$BACKUP_REDIS" == "true" ]] && backup_redis "$backup_stage"
    [[ "$BACKUP_SQLITE" == "true" ]] && backup_sqlite "$backup_stage"
    [[ "$BACKUP_OUTPUT" == "true" ]] && backup_output "$backup_stage"
    [[ "$BACKUP_LOGS" == "true" ]] && backup_logs "$backup_stage"
    [[ "$BACKUP_CONFIGS" == "true" ]] && backup_configs "$backup_stage"

    # Create archive
    local archive_path
    archive_path=$(create_archive "$backup_stage")

    # Verify backup
    verify_backup "$archive_path"

    # Upload to remote if configured
    upload_remote "$archive_path"

    # Cleanup staging
    cleanup_stage "$PROJECT_ROOT/.backup_staging"

    # Cleanup old backups
    cleanup_old_backups

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo ""
    log_success "Backup completed successfully in ${duration}s"
    log_info "Archive: $archive_path"
    log_info "Manifest: ${archive_path}.manifest.json"
}

# ── Entry Point ───────────────────────────────────────────────────────────
main "$@"
