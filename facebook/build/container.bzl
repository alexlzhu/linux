load("//facebook:template.bzl", "template")

def _src_loc(src):
    if "$OUT" in src or "$TMP" in src:
        return src
    if "$(location" in src:
        return src
    return "$(location {})".format(src)

def container_genrule(name, cmd, pre_cmd = "", bind_ro = None, bind_rw = None, overlay_ro = None, overlay_rw = None, tmpfs = None, cacheable = False):
    """Runs the specified shell command in the build container

    This rule runs commands within a systemd-nspawn container based on the
    image built from fbcode/kernel/build.
    It makes it easy to handle mounts without messing with shell arguments to
    systemd-nspawn

    Args:
      name: a unique name for this rule
      bind_ro: list of (source, dest) tuples where 'source' on the host system
               is read-only bind-mounted into the container at 'dest'
               source must be a buck target (it will be used in a location macro)
      bind_rw: see bind_ro
      overlay_ro: list of (source, ..., sourceN, dest) tuples where the source
                  directories on the host system are overlayed into the container at dest
                  source must be a buck target (it will be used in a location macro)
      overlay_rw: list of (source, ..., sourceN, dest) tuples where the source
                  directories on the host system are overlayed into the container at dest
                  writes to dest from inside the container will be written to
                  the last source directory in the tuple
                  source must be a buck target (it will be used in a location macro)
      tmpfs: list of paths to mount as tmpfs within the container
      cacheable: True if the result of this genrule should be saved in the buck cache
    """
    args = ()

    # create a script with the command that we can bind into the container so
    # that it is easy to inspect exactly what will be run inside the container,
    # and to run it inside the -container target manually if necessary
    native.genrule(
        name = name + "-cmd",
        cmd = "echo '#!/bin/bash' > $OUT && chmod +x $OUT && echo '{}' >> $OUT".format(cmd),
        out = "cmd.sh",
    )

    if not bind_ro:
        bind_ro = []
    if not bind_rw:
        bind_rw = []
    if not overlay_ro:
        overlay_ro = []
    if not overlay_rw:
        overlay_rw = []
    if not tmpfs:
        tmpfs = []

    # bind the script into the container
    bind_ro = list(bind_ro)
    bind_ro += [(":{}-cmd".format(name), "/tmp/cmd.sh")]

    bind_ro = [struct(src = _src_loc(src), dst = dst) for src, dst in bind_ro]
    for b in bind_ro:
        if not b.dst.startswith("/ro") and not b.dst.startswith("/tmp"):
            fail("RO mounts not allowed outside of /ro,/tmp (found {})".format(b.dst), attr = "bind_ro")
    bind_rw = [struct(src = _src_loc(src), dst = dst) for src, dst in bind_rw]
    for b in bind_rw:
        if not b.dst.startswith("/rw"):
            fail("RW mounts not allowed outside of /rw (found {})".format(b.dst), attr = "bind_rw")
    overlay_ro = [struct(srcs = ":".join([_src_loc(s) for s in overlay[:-1]]), dst = overlay[-1]) for overlay in overlay_ro]
    for b in overlay_ro:
        if not b.dst.startswith("/ro") and not b.dst.startswith("/tmp"):
            fail("RO overlays not allowed outside of /ro,/tmp (found {})".format(b.dst), attr = "overlay_ro")
    overlay_rw = [struct(srcs = ":".join([_src_loc(s) for s in overlay[:-1]]), dst = overlay[-1]) for overlay in overlay_rw]
    for b in overlay_rw:
        if not b.dst.startswith("/rw"):
            fail("RW overlays not allowed outside of /rw (found {})".format(b.dst), attr = "overlay_rw")

    # find all the host paths that are writable by the container
    all_rw = " ".join([b.src for b in bind_rw] + [o.srcs.split(":")[-1] for o in overlay_rw])
    if "$OUT" not in all_rw:
        fail("container_genrule will not output anything: {}".format(all_rw))

    # before setting up the args with the user's command, generate an executable
    # script that allows a user to drop into a shell in the container, to aid in
    # debugging build changes
    template(
        name = name + "-container",
        src = "//facebook/build:nspawn.sh",
        executable = True,
        variables = struct(
            image = "$(location //facebook/build:build-image)",
            pre_cmd = pre_cmd,
            bind_ro = bind_ro,
            bind_rw = bind_rw,
            overlay_ro = overlay_ro,
            overlay_rw = overlay_rw,
            tmpfs = tmpfs,
        ),
    )

    # reuse the -container executable to run the actual build command
    native.genrule(
        name = name,
        cmd = "mkdir -p $OUT && OUT=$OUT TMP=$TMP $(exe :{}-container) /tmp/cmd.sh".format(name),
        # perhaps unintuitively, defaulting to non-cacheable is actually a performance
        # optimization preventing buck from wasting time computing (in|out)put hashes
        # and compressing potentially thousands of individual files, for example:
        # in the case of running `make` on the kernel, the output hash computing
        # step makes up a significant portion of total rule running time
        cacheable = cacheable,
        out = ".",
    )
