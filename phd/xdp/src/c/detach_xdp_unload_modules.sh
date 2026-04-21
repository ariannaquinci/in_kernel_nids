#!/usr/bin/env bash

set -u

BPFFS_PATH="${BPFFS_PATH:-/sys/fs/bpf/xdp_nids}"
IFACE_ARG="${1:-${XDP_IFACE:-}}"
FORCE=0
UNLOAD_MODULES=1
UNLOAD_TIMEOUT_SECS="${UNLOAD_TIMEOUT_SECS:-5}"

parse_args() {
    local positional=()
    local arg

    for arg in "$@"; do
        case "$arg" in
            --force)
                FORCE=1
                ;;
            --detach-only|--keep-modules|--no-unload)
                UNLOAD_MODULES=0
                ;;
            *)
                positional+=("$arg")
                ;;
        esac
    done

    IFACE_ARG="${positional[0]:-${XDP_IFACE:-}}"
}

if [[ ${EUID:-$(id -u)} -eq 0 ]]; then
    SUDO=()
else
    SUDO=(sudo)
fi

ensure_privileges() {
    if [[ ${#SUDO[@]} -eq 0 ]]; then
        return 0
    fi

    log "richiedo privilegi sudo per detach/unload"
    if ! sudo -v; then
        warn "autenticazione sudo fallita"
        return 1
    fi

    return 0
}

log() {
    printf '[teardown] %s\n' "$*"
}

warn() {
    printf '[teardown] warning: %s\n' "$*" >&2
}

run_quiet() {
    "${SUDO[@]}" "$@" >/dev/null 2>&1
}

run_logged() {
    log "exec: $*"
    "${SUDO[@]}" "$@"
}

run_unload_cmd() {
    if command -v timeout >/dev/null 2>&1; then
        "${SUDO[@]}" timeout "${UNLOAD_TIMEOUT_SECS}s" "$@" >/dev/null 2>&1
    else
        "${SUDO[@]}" "$@" >/dev/null 2>&1
    fi
}

module_loaded() {
    grep -qE "^$1 " /proc/modules
}

module_refcnt() {
    awk -v mod="$1" '$1 == mod { print $3; found = 1 } END { if (!found) print 0 }' /proc/modules
}

module_known_to_kmod() {
    modinfo -n "$1" >/dev/null 2>&1
}

resolve_iface() {
    local iface="${IFACE_ARG:-}"

    if [[ -n "$iface" && -d "/sys/class/net/$iface" ]]; then
        printf '%s\n' "$iface"
        return 0
    fi

    if command -v bpftool >/dev/null 2>&1; then
        iface="$("${SUDO[@]}" bpftool net show 2>/dev/null | awk '
            /dev[[:space:]]/ && /xdp/ {
                for (i = 1; i <= NF; i++) {
                    if ($i == "dev") {
                        print $(i + 1);
                        exit;
                    }
                }
            }')"
        if [[ -n "$iface" && -d "/sys/class/net/$iface" ]]; then
            printf '%s\n' "$iface"
            return 0
        fi
    fi

    iface="$(find /sys/class/net -mindepth 1 -maxdepth 1 -printf '%f\n' | grep -v '^lo$' | head -n1)"
    if [[ -n "$iface" && -d "/sys/class/net/$iface" ]]; then
        printf '%s\n' "$iface"
        return 0
    fi

    return 1
}

detach_xdp() {
    local iface="$1"

    [[ -d "/sys/class/net/$iface" ]] || return 0

    log "detach XDP da $iface"

    if command -v bpftool >/dev/null 2>&1; then
        run_quiet bpftool net detach xdp dev "$iface"
        run_quiet bpftool net detach xdpdrv dev "$iface"
        run_quiet bpftool net detach xdpgeneric dev "$iface"
        run_quiet bpftool net detach xdpoffload dev "$iface"
        run_quiet bpftool net detach generic dev "$iface"
        run_quiet bpftool net detach offload dev "$iface"
    fi

    if command -v ip >/dev/null 2>&1; then
        run_quiet ip link set dev "$iface" xdp off
        run_quiet ip link set dev "$iface" xdpgeneric off
        run_quiet ip link set dev "$iface" xdpdrv off
        run_quiet ip link set dev "$iface" xdpoffload off
    fi

    if command -v tc >/dev/null 2>&1; then
        run_quiet tc qdisc del dev "$iface" clsact
    fi

    # Lascia un attimo al datapath per drenare eventuali riferimenti residui.
    sleep 1
}

cleanup_bpffs() {
    if [[ -e "$BPFFS_PATH" ]]; then
        log "pulizia pin BPF in $BPFFS_PATH"
        run_quiet rm -rf "$BPFFS_PATH"
    fi
}

build_module_list() {
    local mods=()
    local mod

    if [[ -d modules ]]; then
        while IFS= read -r mod; do
            mods+=("$mod")
        done < <(find modules -maxdepth 1 -type f -name '*.ko' -printf '%f\n' | sed 's/\.ko$//' | sort)
    fi

    # Reverse known dependency order for this project: protocol hooks first,
    # auxiliary modules next, and deferred backends last.
    local ordered=()
    for mod in tcp_stream_hook netfilter_hook_udp netfilter_hook udp_nfqueue_gate deferred_analysis_tcp deferred_analysis_udp; do
        if printf '%s\n' "${mods[@]}" | grep -qx "$mod"; then
            ordered+=("$mod")
        fi
    done

    for mod in "${mods[@]}"; do
        if ! printf '%s\n' "${ordered[@]}" | grep -qx "$mod"; then
            ordered+=("$mod")
        fi
    done

    printf '%s\n' "${ordered[@]}"
}

unload_one() {
    local mod="$1"
    local attempt
    local use_modprobe=0

    if ! module_loaded "$mod"; then
        return 0
    fi

    if module_known_to_kmod "$mod"; then
        use_modprobe=1
    fi

    log "scarico modulo $mod"
    for attempt in $(seq 1 25); do
        if [[ "$use_modprobe" -eq 1 ]]; then
            if run_unload_cmd modprobe -r "$mod"; then
                break
            fi

            warn "tentativo $attempt: modprobe -r $mod fallito o scaduto (refcnt=$(module_refcnt "$mod"))"
        fi

        if run_unload_cmd rmmod "$mod"; then
            break
        fi

        warn "tentativo $attempt: rmmod $mod fallito o scaduto (refcnt=$(module_refcnt "$mod"))"

        if [[ "$FORCE" -eq 1 ]] && run_unload_cmd rmmod -f "$mod"; then
            break
        fi

        sleep 0.2
    done

    if module_loaded "$mod"; then
        warn "modulo $mod ancora carico (refcnt=$(module_refcnt "$mod"))"
        return 1
    fi

    log "modulo $mod scaricato"

    return 0
}

main() {
    local iface=""
    local failures=0
    local mod

    parse_args "$@"

    if ! ensure_privileges; then
        return 1
    fi

    if iface="$(resolve_iface)"; then
        detach_xdp "$iface"
    else
        warn "interfaccia non individuata automaticamente, salto il detach XDP"
    fi

    cleanup_bpffs

    if [[ "$UNLOAD_MODULES" -eq 0 ]]; then
        log "detach completato, moduli kernel lasciati caricati"
        return 0
    fi

    while IFS= read -r mod; do
        [[ -n "$mod" ]] || continue
        if ! unload_one "$mod"; then
            failures=1
        fi
    done < <(build_module_list)

    if [[ "$failures" -ne 0 ]]; then
        warn "teardown incompleto; riprova tra un attimo oppure usa --force se vuoi tentare un unload forzato"
        return 1
    fi

    log "teardown completato"
}

main "$@"
