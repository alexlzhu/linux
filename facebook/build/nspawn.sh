#!/usr/bin/env bash
set -e

OUT="${OUT}"
TMP="${TMP}"

if [ -z "$OUT" ]; then
    OUT="$(mktemp -d)"
fi
if [ -z "$TMP" ]; then
    TMP="$(mktemp -d)"
fi

# TODO: debug why systemd-nspawn hangs on Sandcastle when trying to mount an
# image file
# just do it here and pass --directory so that it works
mnt="$(mktemp -d)"
sudo mount -o ro "{{ .image }}" "$mnt"

function cleanup {
    sudo umount "$mnt"
    rm -rf "$mnt"
    sudo chown -R "$(whoami)" "$OUT"
    find "$OUT" -xtype l -delete
    sudo chown -R "$(whoami)" "$TMP"
    find "$TMP" -xtype l -delete
}
trap cleanup EXIT

{{ .pre_cmd }}
UNIFIED_CGROUP_HIERARCHY=1 sudo systemd-nspawn \
    `# this ends up in the resulting kernel image and is nicer to look at` \
    `# than some random container name` \
    --hostname="$HOSTNAME" \
    --directory="$mnt" \
    `# let the container do whatever it wants and throw away any changes after it's done` \
    --volatile=overlay \
    `# don't register with systemd-machined` \
    --keep-unit --register=no \
    `# don't look for .nspawn files to configure settings` \
    --settings=no \
    `# don't log container journal to the host` \
    --link-journal=no \
    `# don't let the container hit the network and potentially bring in` \
    `# unspecified external dependencies` \
    --private-network \
    `# start bash in /, otherwise it goes into /root` \
    --chdir=/ \
    {{- range .bind_ro }}
    --bind-ro={{ .src }}:{{ .dst }} \
    {{- end }}
    {{- range .bind_rw }}
    --bind={{ .src }}:{{ .dst }} \
    {{- end }}
    {{- range .overlay_ro }}
    --overlay-ro={{ .srcs }}:{{ .dst }} \
    {{- end }}
    {{- range .overlay_rw }}
    --overlay={{ .srcs }}:{{ .dst }} \
    {{- end }}
    {{- range .tmpfs }}
    --tmpfs={{ . }} \
    {{- end }}
    $@
