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
printf 'Starting SR for http://127.0.0.1:8787/admin\nSR data directory: %s\n' "$data_dir"
printf '%s\n' 'SR reports when it is listening; press Ctrl-C to stop.'
exec "$1" -m scarcity_router.control_server --host 127.0.0.1 --port 8787 --data-dir "$data_dir"
