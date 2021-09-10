load("//facebook/config:defs.bzl", "config_name")
load("//facebook/build:container.bzl", "container_genrule")
load("//facebook/build:modules.bzl", "module", "modules")
load("//facebook:template.bzl", "template")

def buildinfo():
    # read runtime build info from buckconfig, this allows the wrapper to insert
    # information about git state that is not accessible to buck (the same way eg
    # fbpkg builds work)
    # if invoked as just `buck` (not via the wrapper) these values will be faked
    # with the values in .buckconfig, which allows for faster iteration on local
    # builds for testing purposes
    fbk_tag = native.read_config("build_info", "fbk_tag")

    # eg: 5.2.9
    kernelversion = native.read_config("build_info", "kernelversion")
    # eg: 5.2
    major = ".".join(kernelversion.split(".")[:2])

    rc_version = None
    hotfix = None

    # parse the rc version and fbk name out of the tag (eg v5.2-fbk1-rc1)
    fbk_pieces = fbk_tag.split("-")
    if len(fbk_pieces) > 4 or len(fbk_pieces) < 2:
        fail("expected either 2 to 4 pieces in fbk_tag: '{}', found {}".format(fbk_tag, fbk_pieces))

    if len(fbk_pieces) == 4:
        if "hotfix" not in fbk_pieces[-1]:
            fail("fbk_tag have to look like v5.2-fbk1[-rc1|-rc1-hotfix1|-hotfix1], got: %s" % fbk_tag)
        else:
            hotfix = fbk_pieces[-1]
            rc_version = fbk_pieces[-2]
    elif len(fbk_pieces) == 3:
      if "hotfix" in fbk_pieces[-1]:
        hotfix = fbk_pieces[-1]
      elif "rc" in fbk_pieces[-1]:
        rc_version = fbk_pieces[-1]
      else:
        fail("fbk_tag supposed to have rc or hotfix suffix, it is: %s" % fbk_tag)

    return struct(
        major = major,
        kernelversion = kernelversion,
        # eg: 1920_gd7e71ef6c6bd
        gittish = native.read_config("build_info", "gittish"),
        # eg: fbk1
        fbk = fbk_pieces[1],
        # eg: rc1
        rc_version = rc_version,
        # Historically the rpm_number was a monotonically increasing integer.
        # Starting with 5.6 this is constantly set to 0, because it is not
        # required anymore.
        rpm_number = "0",
        hotfix = hotfix,
        # custom_tag allows a user to inject an arbitrary string into the
        # EXTRAVERSION, for example to indicate -debug
        custom_tag = native.read_config("build_info", "custom_tag", ""),
    )

def extra_version(info, flavor, debug_opt):
    version = info.rpm_number + "_" + info.fbk
    if flavor != None:
        version += "_" + flavor
    if info.rc_version != None:
        version += "_" + info.rc_version
    if debug_opt != None:
        version += "_debug_" + debug_opt
    if info.custom_tag:
        version += "_" + info.custom_tag
    version += "_" + info.gittish
    return version

def kernel(arch, flavor = None, debug = None, headers_rpm = True, devel_rpm = True, build_modules = True, extra_srcs = None, labels = None):
    name = config_name(arch = arch, flavor = flavor, debug = debug)
    config_target = "//facebook/config:" + config_name(arch, flavor = flavor, debug = debug)

    if not labels:
        labels = []

    info = buildinfo()
    uname = info.kernelversion + "-" + extra_version(info, flavor, debug)

    if not extra_srcs:
        extra_srcs = []

    llvm_macro = ""
    if flavor:
        if "clangtrain" in flavor:
            llvm_macro = "LLVM=1"
        elif "clang" in flavor:
            extra_srcs += [("$(location //facebook/build:clang-train-data)", "/tmp/vmlinux.profdata")]
            llvm_macro = "LLVM=1 CFLAGS_PGO_CLANG=-fprofile-use=/tmp/vmlinux.profdata"

    # convenience rule to inspect uname
    native.genrule(
        name = name + "-uname",
        cmd = "echo {} > $OUT".format(uname),
        out = "uname",
    )

    template(
        name = name + "-rpmspec",
        src = "//facebook/build:fb-kernel.spec.template",
        variables = struct(
            version = info.kernelversion,
            release = extra_version(info, flavor, debug),
            uname = uname,
            flavor = flavor or "",
            modules = build_modules,
            headers_rpm = headers_rpm,
            devel_rpm = devel_rpm,
        ),
    )

    native.genrule(
        name = name + "-config-overlay",
        cmd = "mkdir -p $OUT && cp $(location {}) $OUT/.config".format(config_target),
        out = ".",
    )

    sign = native.read_config('kernel', 'sign_mod', 'false')
    sign_key = native.read_config('kernel', 'sign_mod_key', 'autograph-test')
    # run make directly before rpmbuild so that outputs may be consumed without
    # first building an rpm, and to better leverage caching and error reporting
    container_genrule(
        name = name + "-compile",
        cmd = """cd /ro/source
        # there needs to be a writable .config
        cp /tmp/config /rw/compile/.config
        make EXTRAVERSION=-{extra} O=/rw/compile {llvm_macro} olddefconfig
        make EXTRAVERSION=-{extra} O=/rw/compile {llvm_macro} -s -j`nproc`
        """.format(extra = extra_version(info, flavor, debug), llvm_macro = llvm_macro),
        bind_ro = [
            ("//:sources", "/ro/source"),
            (config_target, "/tmp/config"),
            # copy in the uname target to enforce that necessary pieces get
            # re-built when the release name changes
            (":{}-uname".format(name), "/tmp/uname"),
        ] + extra_srcs,
        bind_rw = [("$OUT", "/rw/compile")],
    )
    native.genrule(
        name = name + "-sign",
        cmd = """
        if [ "{sign}" == "true" ]; then
          # we have actual modules to sign - lol and kdump doesn't have any
          if [ "`find $(location :{name}-compile) -name '*.ko' -print -quit`" != "" ]; then
            autograph_client.par kmod --sign-key {sign_key} --kernel-tree $(location :{name}-compile)
          fi
        fi
        """.format(sign = sign, name = name, sign_key = sign_key),
        out = ".",
    )
    # the vmlinuz target can be useful to be consumed directly, such as in
    # fbcode/tupperware/vmtest to launch a qemu vm from a vmlinuz extracted from
    # an rpm generated by the same release build process
    container_genrule(
        name = name + "-vmlinuz",
        cmd = "cd /rw/compile && cp `make -s image_name` /rw/out/vmlinuz",
        bind_ro = [
            # this needs to be bound to the original location as well as in the
            # overlay, since there will be some hardcoded paths in Makefiles in
            # the output directory (which we need for `make -s image_name`)
            ("//:sources", "/ro/source"),
        ],
        overlay_rw = [
            (":{}-compile".format(name), "//:sources", "$TMP", "/rw/compile"),
        ],
        bind_rw = [("$OUT", "/rw/out")],
    )

    # build the kernel in a systemd container based on the container image built
    # with tupperware's image build infra in fbcode
    container_genrule(
        name = name + "-rpmbuild",
        cmd = """rpmbuild \\
            --noclean \\
            -bb /ro/kernel.spec
            cp -R /root/rpmbuild/RPMS/x86_64/*.rpm /rw/rpms
            #  $(location :{}-sign) that is needed only for dependency
        """.format(name),
        bind_ro = [
            (":{}-rpmspec".format(name), "/ro/kernel.spec"),
        ],
        overlay_rw = [
            (":{}-compile".format(name), "//:sources", "$TMP", "/rw/kernel"),
        ],
        bind_rw = [
            ("$OUT", "/rw/rpms"),
        ],
    )

    # # make additional targets for each of the rpms - this makes them easier to
    # # consume without knowing what the full name will be a-priori
    native.genrule(
        name = name + ".rpm",
        cmd = "cp $(location :{}-rpmbuild)/kernel-{}.x86_64.rpm $OUT".format(name, uname),
        out = "kernel.rpm",
        visibility = ["PUBLIC"],
    )
    native.genrule(
        name = name + "-devel.rpm",
        cmd = "cp $(location :{}-rpmbuild)/kernel-devel-*.rpm $OUT".format(name),
        out = "kernel-devel.rpm",
        visibility = ["PUBLIC"],
    )
    native.genrule(
        name = name + "-headers.rpm",
        cmd = "cp $(location :{}-rpmbuild)/kernel-headers-*.rpm $OUT".format(name),
        out = "kernel-headers.rpm",
        visibility = ["PUBLIC"],
    )

    # allow an escape hatch to not build modules, even if they exist in the config
    kmods = [m for m in modules if info.major in m.kernels]
    # if a module is set to build on only certain flavors, filter it out
    kmods = [m for m in kmods if flavor in m.flavors or not m.flavors]
    if build_modules and kmods:
        cmd_str_list = []

        for mod in kmods:
            deps = []
            d = 0
            for dep in mod.depends:
                d += 1
                tpl = (
                    "$(location :{}-module_{}-rpmbuild)".format(name, dep),
                    "/tmp/dependency-{}-{}".format(d, dep)
                )
                deps.append(tpl)
            module(
                name = "{}-module_{}".format(name, mod.name),
                module = mod,
                kernel_devel = "$(location :{}-devel.rpm)".format(name),
                uname = uname,
                dependencies = deps,
            )
            cmd_str_list.append("$(location :{}-module_{})/*.rpm".format(name, mod.name))

        native.genrule(
            name = name + "-modules",
            out = ".",
            cmd = "mkdir -p $OUT && cp {} $OUT/".format(" ".join(cmd_str_list)),
        )
        module_rpms = "$(location :{}-modules)/*.rpm".format(name)
    else:
        module_rpms = " "

    # the named output should be a directory of all RPMs for the kernel,
    # including modules if any
    native.genrule(
        name = name,
        type = "kernel",
        out = ".",
        cmd = "mkdir -p $OUT && cp $(location :{}-rpmbuild)/*.rpm {} $OUT/".format(name, module_rpms),
        labels = labels,
    )
