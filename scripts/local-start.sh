#!/bin/sh
set -eu

if [ "$#" -ne 1 ] || [ "${1#/}" = "$1" ] || [ ! -x "$1" ]; then
    printf '%s\n' 'Usage: scripts/local-start.sh /absolute/path/to/sr-python' >&2
    exit 2
fi

case ${XDG_DATA_HOME:-} in
    /*) data_home=$XDG_DATA_HOME ;;
    *)
        case ${HOME:-} in
            /*) data_home=$HOME/.local/share ;;
            *) printf '%s\n' 'An absolute HOME or XDG_DATA_HOME is required.' >&2; exit 2 ;;
        esac
        ;;
esac
data_dir=$data_home/scarcity-router/server
mi_dir=${FOUNDRY_MI_DIR:-}
mi_digest=${FOUNDRY_MI_SHA256:-}
if [ -n "${FOUNDRY_MI_IMAGE_ID:-}" ]; then
    printf '%s\n' 'FOUNDRY_MI_IMAGE_ID is only supported for the Compose path.' >&2
    exit 2
fi
if [ -n "$mi_dir" ] || [ -n "$mi_digest" ]; then
    if [ -z "$mi_dir" ] || [ -z "$mi_digest" ]; then
        printf '%s\n' 'Native MI requires FOUNDRY_MI_DIR and FOUNDRY_MI_SHA256 together.' >&2
        exit 2
    fi
    script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
    "$1" -B "$script_dir/local_runtime.py" --native-mi-check
    set -- "$1" --mi-config "$mi_dir/trust.json"
fi
printf 'Starting SR for http://127.0.0.1:8787/admin\nSR data directory: %s\n' "$data_dir"
printf '%s\n' 'SR reports when it is listening; press Ctrl-C to stop.'
python=$1
shift
exec "$python" -m scarcity_router.control_server --host 127.0.0.1 --port 8787 --data-dir "$data_dir" "$@"
