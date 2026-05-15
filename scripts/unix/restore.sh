#!/usr/bin/env bash
# =============================================================================
# Cyber Security Test Pipeline - Restore Script
# =============================================================================
# Restores Redis data, SQLite databases, and output data from a backup
# archive. Supports local and remote backup sources.
# =============================================================================

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
CONFIG_FILE="$PROJECT_ROOT/configs/backup-config.json"
LOG_FILE="$PROJECT_ROOT/logs/restore_$(date +%Y%m%d_%H%M%S).log"

# ── Colors for output ──────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ── Variables ──────────────────────────────────────────────────────────────
BACKUP_FILE=""
RESTORE_REDIS=true
RESTORE_SQLITE=true
RESTORE_OUTPUT=true
RESTORE_LOGS=true
RESTORE_CONFIGS=true
FORCE=false
DRY_RUN=false
RESTORE_DIR=""
REDIS_HOST="${REDIS_HOST:-localhost}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_PASSWORD=""

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

# ── Usage ──────────────────────────────────────────────────────────────────
usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS] <backup_archive>

Restore Cyber Security Test Pipeline from a backup archive.

Options:
    -f, --file ARCHIVE      Path to backup archive (.tar.gz or .tar)
    -r, --redis             Restore Redis data (default: true)
    -s, --sqlite            Restore SQLite databases (default: true)
    -o, --output            Restore output data (default: true)
    -l, --logs              Restore logs (default: true)
    -c, --configs           Restore configurations (default: true)
    --no-redis              Skip Redis restore
    --no-sqlite             Skip SQLite restore
    --no-output             Skip output restore
    --no-logs               Skip logs restore
    --no-configs            Skip configs restore
    --force                 Skip confirmation prompts
    --dry-run               Show what would be restored without doing it
    -h, --help              Show this help message

Examples:
    $(basename "$0") -f backups/backup_20260404_120000.tar.gz
    $(basename "$0") --file backups/backup_20260404_120000.tar.gz --no-redis
    $(basename "$0") --dry-run -f backups/backup_20260404_120000.tar.gz
EOF
    exit 0
}

# ── Parse Arguments ───────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -f|--file)
                BACKUP_FILE="$2"
                shift 2
                ;;
            --no-redis)
                RESTORE_REDIS=false
                shift
                ;;
            --no-sqlite)
                RESTORE_SQLITE=false
                shift
                ;;
            --no-output)
                RESTORE_OUTPUT=false
                shift
                ;;
            --no-logs)
                RESTORE_LOGS=false
                shift
                ;;
            --no-configs)
                RESTORE_CONFIGS=false
                shift
                ;;
            --force)
                FORCE=true
                shift
                ;;
            --dry-run)
                DRY_RUN=true
                shift
                ;;
            -h|--help)
                usage
                ;;
            *)
                if [[ -z "$BACKUP_FILE" ]]; then
                    BACKUP_FILE="$1"
                else
                    log_error "Unknown argument: $1"
                    usage
                fi
                shift
                ;;
        esac
    done

    if [[ -z "$BACKUP_FILE" ]]; then
        log_error "No backup file specified"
        usage
    fi
}

# ── Pre-flight Checks ─────────────────────────────────────────────────────
preflight() {
    log_info "Running pre-flight checks..."

    mkdir -p "$(dirname "$LOG_FILE")"

    # Verify backup file exists
    if [[ ! -f "$BACKUP_FILE" ]]; then
        log_error "Backup file not found: $BACKUP_FILE"
        exit 1
    fi

    # Check required tools
    local required_tools=("tar")
    for tool in "${required_tools[@]}"; do
        if ! command -v "$tool" &>/dev/null; then
            log_error "Required tool '$tool' not found"
            exit 1
        fi
    done

    # Verify archive integrity
    log_info "Verifying backup archive integrity..."
    if ! tar -tzf "$BACKUP_FILE" &>/dev/null && ! tar -tf "$BACKUP_FILE" &>/dev/null; then
        log_error "Backup archive is corrupted or invalid!"
        exit 1
    fi

    # Verify checksum if available
    if [[ -f "${BACKUP_FILE}.sha256" ]]; then
        log_info "Verifying SHA256 checksum..."
        if command -v sha256sum &>/dev/null; then
            if sha256sum -c "${BACKUP_FILE}.sha256" &>/dev/null; then
                log_success "Checksum verification passed"
            else
                log_error "Checksum verification failed! Archive may be corrupted."
                exit 1
            fi
        fi
    fi

    # Read manifest if available
    if [[ -f "${BACKUP_FILE}.manifest.json" ]]; then
        log_info "Backup manifest found:"
        if command -v jq &>/dev/null; then
            jq '.' "${BACKUP_FILE}.manifest.json" | head -20
        else
            cat "${BACKUP_FILE}.manifest.json"
        fi
    fi

    log_success "Pre-flight checks passed"
}

# ── Extract Archive ───────────────────────────────────────────────────────
extract_archive() {
    log_info "Extracting backup archive..."

    RESTORE_DIR="$PROJECT_ROOT/.restore_staging/restore_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$RESTORE_DIR"

    tar -xf "$BACKUP_FILE" -C "$RESTORE_DIR" 2>/dev/null

    # Find the extracted backup directory
    local backup_dir
    backup_dir=$(find "$RESTORE_DIR" -maxdepth 1 -type d -name "backup_*" | head -1)

    if [[ -z "$backup_dir" ]]; then
        log_error "Could not find backup directory in archive"
        exit 1
    fi

    RESTORE_DIR="$backup_dir"
    log_info "Archive extracted to: $RESTORE_DIR"
}

# ── Confirm Restore ───────────────────────────────────────────────────────
confirm_restore() {
    if [[ "$FORCE" == "true" ]]; then
        return 0
    fi

    echo ""
    log_warn "This will restore data from: $BACKUP_FILE"
    log_warn "Current data may be overwritten!"
    echo ""

    [[ "$RESTORE_REDIS" == "true" ]] && echo "  [✓] Redis data" || echo "  [✗] Redis data (skipped)"
    [[ "$RESTORE_SQLITE" == "true" ]] && echo "  [✓] SQLite databases" || echo "  [✗] SQLite databases (skipped)"
    [[ "$RESTORE_OUTPUT" == "true" ]] && echo "  [✓] Output data" || echo "  [✗] Output data (skipped)"
    [[ "$RESTORE_LOGS" == "true" ]] && echo "  [✓] Logs" || echo "  [✗] Logs (skipped)"
    [[ "$RESTORE_CONFIGS" == "true" ]] && echo "  [✓] Configurations" || echo "  [✗] Configurations (skipped)"
    echo ""

    read -rp "Are you sure you want to continue? (yes/no): " confirm
    if [[ "$confirm" != "yes" ]]; then
        log_info "Restore cancelled by user"
        exit 0
    fi
}

# ── Dry Run ───────────────────────────────────────────────────────────────
dry_run() {
    log_info "=== DRY RUN MODE ==="
    log_info "Would restore from: $BACKUP_FILE"
    log_info "Extracted contents:"

    tar -tzf "$BACKUP_FILE" 2>/dev/null || tar -tf "$BACKUP_FILE" 2>/dev/null

    echo ""
    [[ "$RESTORE_REDIS" == "true" ]] && log_info "Would restore: Redis data"
    [[ "$RESTORE_SQLITE" == "true" ]] && log_info "Would restore: SQLite databases"
    [[ "$RESTORE_OUTPUT" == "true" ]] && log_info "Would restore: Output data"
    [[ "$RESTORE_LOGS" == "true" ]] && log_info "Would restore: Logs"
    [[ "$RESTORE_CONFIGS" == "true" ]] && log_info "Would restore: Configurations"

    log_info "=== END DRY RUN ==="
    exit 0
}

# ── Restore Redis ─────────────────────────────────────────────────────────
restore_redis() {
    local redis_dir="$RESTORE_DIR/redis"

    if [[ ! -d "$redis_dir" ]]; then
        log_warn "Redis backup not found in archive, skipping"
        return 0
    fi

    log_info "Starting Redis restore..."

    # Check if Redis is running
    if command -v redis-cli &>/dev/null; then
        local redis_cmd="redis-cli -h $REDIS_HOST -p $REDIS_PORT"
        [[ -n "$REDIS_PASSWORD" ]] && redis_cmd="$redis_cmd -a $REDIS_PASSWORD"

        if $redis_cmd ping &>/dev/null 2>&1; then
            log_warn "Redis is running. Flushing all databases before restore..."
            if [[ "$FORCE" == "true" ]]; then
                $redis_cmd FLUSHALL 2>/dev/null || true
            else
                read -rp "Flush all Redis databases before restore? (yes/no): " flush_confirm
                if [[ "$flush_confirm" == "yes" ]]; then
                    $redis_cmd FLUSHALL 2>/dev/null || true
                else
                    log_warn "Skipping Redis flush, data will be merged"
                fi
            fi
        else
            log_warn "Redis is not running. Restore will prepare files for next startup."
        fi
    fi

    # Restore from dump file
    if [[ -f "$redis_dir/dump.rdb" ]]; then
        log_info "Restoring Redis from dump.rdb..."

        # Try to find Redis data directory
        if command -v redis-cli &>/dev/null; then
            local redis_cmd="redis-cli -h $REDIS_HOST -p $REDIS_PORT"
            [[ -n "$REDIS_PASSWORD" ]] && redis_cmd="$redis_cmd -a $REDIS_PASSWORD"

            local redis_data_dir
            redis_data_dir=$($redis_cmd CONFIG GET dir 2>/dev/null | tail -1 || echo "")

            if [[ -n "$redis_data_dir" && -d "$redis_data_dir" ]]; then
                cp "$redis_dir/dump.rdb" "$redis_data_dir/dump.rdb"
                log_info "Dump file restored to $redis_data_dir"
                log_info "Restart Redis to apply changes"
            fi
        fi

        # Also restore Docker volume if applicable
        if docker volume ls --format '{{.Name}}' 2>/dev/null | grep -q "redis"; then
            log_info "Restoring Redis Docker volume..."
            docker run --rm \
                -v "$(docker volume ls --format '{{.Name}}' | grep redis | head -1):/redis-data" \
                -v "$redis_dir:/backup" \
                alpine sh -c "rm -rf /redis-data/* && cp /backup/dump.rdb /redis-data/" 2>/dev/null || true
            log_info "Redis Docker volume restored"
        fi
    fi

    # Restore from volume backup if available
    if [[ -f "$redis_dir/redis-volume.tar.gz" ]]; then
        log_info "Restoring Redis from volume backup..."
        if docker volume ls --format '{{.Name}}' 2>/dev/null | grep -q "redis"; then
            docker run --rm \
                -v "$(docker volume ls --format '{{.Name}}' | grep redis | head -1):/redis-data" \
                -v "$redis_dir:/backup" \
                alpine tar xzf /backup/redis-volume.tar.gz -C /redis-data 2>/dev/null || true
        fi
    fi

    log_success "Redis restore completed"
}

# ── Restore SQLite ────────────────────────────────────────────────────────
restore_sqlite() {
    local sqlite_dir="$RESTORE_DIR/sqlite"

    if [[ ! -d "$sqlite_dir" ]]; then
        log_warn "SQLite backup not found in archive, skipping"
        return 0
    fi

    log_info "Starting SQLite restore..."

    # Restore database files
    for db_file in "$sqlite_dir"/*.db; do
        if [[ ! -f "$db_file" ]]; then
            continue
        fi

        local db_name
        db_name="$(basename "$db_file")"
        # Remove _backup_TIMESTAMP suffix if present
        local original_name
        original_name=$(echo "$db_name" | sed 's/_backup_[0-9_]*//')

        # Determine target path
        local target_path="$PROJECT_ROOT/data/$original_name"

        # Create target directory if needed
        mkdir -p "$(dirname "$target_path")"

        # Verify database integrity before restoring
        if command -v sqlite3 &>/dev/null; then
            log_info "Verifying database integrity: $db_name"
            local integrity
            integrity=$(sqlite3 "$db_file" "PRAGMA integrity_check;" 2>/dev/null || echo "unknown")
            if [[ "$integrity" == "ok" ]]; then
                log_info "Database integrity check passed"
            else
                log_warn "Database integrity check result: $integrity"
            fi
        fi

        # Backup current database before overwriting
        if [[ -f "$target_path" ]]; then
            local backup_path="${target_path}.pre_restore_$(date +%Y%m%d_%H%M%S)"
            cp "$target_path" "$backup_path"
            log_info "Current database backed up to: $backup_path"
        fi

        cp "$db_file" "$target_path"
        log_info "Restored: $target_path"

        # Restore WAL and SHM files if they exist
        local wal_file="$sqlite_dir/${db_name}-wal"
        local shm_file="$sqlite_dir/${db_name}-shm"
        [[ -f "$wal_file" ]] && cp "$wal_file" "${target_path}-wal"
        [[ -f "$shm_file" ]] && cp "$shm_file" "${target_path}-shm"
    done

    # Restore Alembic migrations
    if [[ -d "$sqlite_dir/alembic" ]]; then
        log_info "Restoring Alembic migrations..."
        if [[ -d "$PROJECT_ROOT/alembic" ]]; then
            local alembic_backup="$PROJECT_ROOT/alembic.pre_restore_$(date +%Y%m%d_%H%M%S)"
            cp -r "$PROJECT_ROOT/alembic" "$alembic_backup"
            log_info "Current alembic backed up to: $alembic_backup"
        fi
        rm -rf "$PROJECT_ROOT/alembic"
        cp -r "$sqlite_dir/alembic" "$PROJECT_ROOT/alembic"
        log_info "Alembic migrations restored"
    fi

    log_success "SQLite restore completed"
}

# ── Restore Output ────────────────────────────────────────────────────────
restore_output() {
    local output_dir="$RESTORE_DIR/output"

    if [[ ! -d "$output_dir" ]]; then
        log_warn "Output backup not found in archive, skipping"
        return 0
    fi

    log_info "Starting output data restore..."

    for item in "$output_dir"/*; do
        if [[ ! -e "$item" ]]; then
            continue
        fi

        local name
        name="$(basename "$item")"
        local target_path="$PROJECT_ROOT/output/$name"

        # Backup current output if exists
        if [[ -e "$target_path" ]]; then
            local backup_path="${target_path}.pre_restore_$(date +%Y%m%d_%H%M%S)"
            if [[ -d "$target_path" ]]; then
                cp -r "$target_path" "$backup_path"
            else
                cp "$target_path" "$backup_path"
            fi
            log_info "Current output backed up to: $backup_path"
        fi

        if [[ -d "$item" ]]; then
            rm -rf "$target_path"
            cp -r "$item" "$target_path"
        else
            cp "$item" "$target_path"
        fi

        log_info "Restored output: $target_path"
    done

    log_success "Output data restore completed"
}

# ── Restore Logs ──────────────────────────────────────────────────────────
restore_logs() {
    local logs_dir="$RESTORE_DIR/logs"

    if [[ ! -d "$logs_dir" ]]; then
        log_warn "Logs backup not found in archive, skipping"
        return 0
    fi

    log_info "Starting logs restore..."

    for item in "$logs_dir"/*; do
        if [[ ! -e "$item" ]]; then
            continue
        fi

        local name
        name="$(basename "$item")"
        local target_path="$PROJECT_ROOT/logs/$name"

        mkdir -p "$(dirname "$target_path")"

        if [[ -d "$item" ]]; then
            cp -r "$item" "$target_path" 2>/dev/null || true
        else
            cp "$item" "$target_path" 2>/dev/null || true
        fi

        log_info "Restored logs: $target_path"
    done

    log_success "Logs restore completed"
}

# ── Restore Configs ───────────────────────────────────────────────────────
restore_configs() {
    local config_dir="$RESTORE_DIR/configs"

    if [[ ! -d "$config_dir" ]]; then
        log_warn "Configs backup not found in archive, skipping"
        return 0
    fi

    log_info "Starting configuration restore..."

    for item in "$config_dir"/*; do
        if [[ ! -e "$item" ]]; then
            continue
        fi

        local name
        name="$(basename "$item")"
        local target_path="$PROJECT_ROOT/$name"

        # Backup current config if exists
        if [[ -e "$target_path" ]]; then
            local backup_path="${target_path}.pre_restore_$(date +%Y%m%d_%H%M%S)"
            if [[ -d "$target_path" ]]; then
                cp -r "$target_path" "$backup_path"
            else
                cp "$target_path" "$backup_path"
            fi
            log_info "Current config backed up to: $backup_path"
        fi

        if [[ -d "$item" ]]; then
            rm -rf "$target_path"
            cp -r "$item" "$target_path"
        else
            cp "$item" "$target_path"
        fi

        # Set secure permissions for .env
        if [[ "$name" == ".env" ]]; then
            chmod 600 "$target_path"
        fi

        log_info "Restored config: $target_path"
    done

    log_success "Configuration restore completed"
}

# ── Cleanup ───────────────────────────────────────────────────────────────
cleanup() {
    if [[ -n "${RESTORE_DIR:-}" && -d "$RESTORE_DIR" ]]; then
        # Go up to the staging directory
        local staging_dir
        staging_dir="$(dirname "$RESTORE_DIR")"
        if [[ "$staging_dir" == *".restore_staging" ]]; then
            rm -rf "$staging_dir"
            log_info "Cleanup completed"
        fi
    fi
}

# ── Post-Restore ──────────────────────────────────────────────────────────
post_restore() {
    log_info "Post-restore tasks..."

    # Run database migrations if alembic was restored
    if [[ -f "$PROJECT_ROOT/alembic.ini" ]] && command -v alembic &>/dev/null; then
        log_info "Checking for pending database migrations..."
        cd "$PROJECT_ROOT"
        alembic upgrade head 2>/dev/null || log_warn "Alembic migration failed, run manually"
    fi

    # Restart services if Docker is available
    if command -v docker &>/dev/null && command -v docker-compose &>/dev/null; then
        log_info "Services may need to be restarted to apply changes"
        log_info "Run: docker-compose restart"
    fi

    log_success "Post-restore tasks completed"
}

# ── Main ──────────────────────────────────────────────────────────────────
main() {
    local start_time
    start_time=$(date +%s)

    echo -e "${BLUE}"
    echo "╔══════════════════════════════════════════════════════════╗"
    echo "║       Cyber Security Test Pipeline - Restore            ║"
    echo "╚══════════════════════════════════════════════════════════╝"
    echo -e "${NC}"

    # Parse arguments
    parse_args "$@"

    log_info "Starting restore at $(date)"
    log_info "Backup file: $BACKUP_FILE"

    # Pre-flight checks
    preflight

    # Dry run mode
    if [[ "$DRY_RUN" == "true" ]]; then
        dry_run
    fi

    # Extract archive
    extract_archive

    # Confirm restore
    confirm_restore

    # Set up cleanup trap
    trap cleanup EXIT

    # Execute restores
    [[ "$RESTORE_REDIS" == "true" ]] && restore_redis
    [[ "$RESTORE_SQLITE" == "true" ]] && restore_sqlite
    [[ "$RESTORE_OUTPUT" == "true" ]] && restore_output
    [[ "$RESTORE_LOGS" == "true" ]] && restore_logs
    [[ "$RESTORE_CONFIGS" == "true" ]] && restore_configs

    # Post-restore tasks
    post_restore

    local end_time
    end_time=$(date +%s)
    local duration=$((end_time - start_time))

    echo ""
    log_success "Restore completed successfully in ${duration}s"
    log_info "Please verify your data and restart services if needed"
}

# ── Entry Point ───────────────────────────────────────────────────────────
main "$@"
