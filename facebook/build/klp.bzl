load("//facebook/build:container.bzl", "container_genrule")
load("//:defs.bzl", "buildinfo")

def klp():
    """
    Generate targets for creating kernel live patches. Callers may specify the
    following configuration parameters:
      - patch_to: A tag that we will be patching to. If this option is not
        specified, the current commit (HEAD) will be assumed. The tag being
        patched to must be suffixed with -hotfix<num>.
      - patch_from: A tag that we will be patching from. If this option is not
        specified, the from tag will be the tag used in patch_to, without the
        -hotfix<num> suffix.
      - flavor: The flavor for the kernel. This is the same flavor that may be
        specified in any other kernel build type.
      - label: A label to apply to the build.
      - sign: Whether the resulting klp module should be signed. Must be set to
        'true' for the module to be signed.
      - sign_key: The key to use when signing the KLP module.
    """
    # Parameters passed to BUCK.
    patch_to = native.read_config("klp", "patch_to", None)
    patch_from = native.read_config("klp", "patch_from", None)
    flavor=native.read_config("klp", "flavor", None)
    label=native.read_config("klp", "label", None)
    sign = native.read_config('kernel', 'sign_mod', 'false')
    sign_key = native.read_config('kernel', 'sign_mod_key', 'hsm-test-key')

    # Generate targets for the commit being patched to. The commit *must* have a
    # tag that is suffixed with -hotfix<num>, regardless of whether the patch_to
    # option is specified by the user when invoking BUCK.
    to_cmd = """
      HOME=/dev/null git show-ref --tags -d
      | grep hotfix
      | grep `HOME=/dev/null git rev-parse HEAD`
      | awk -F '[ /]' '{print $NF}'
      > $OUT"""
    if patch_to:
      to_cmd = "echo {} > $OUT".format(patch_to)

    notempty_cmd = " && [ -s $OUT ] || exit 1"

    native.genrule(
        name="to_tag",
        cmd=to_cmd + notempty_cmd,
        out="to_tag",
        cacheable=False,
    )

    # Extract the hotfix<num> portion of the tag. This will be stripped when
    # generating the target for the from_tag.
    native.genrule(
        name="hotfix",
        cmd="cat $(location :to_tag) | sed -e 's|.*\\(hotfix[0-9]*\\).*|\\1|g' > $OUT" + notempty_cmd,
        out="hotfix",
        cacheable=False,
    )

    # Extract the baseline from_tag from which we're creating the patch. The
    # from_tag (unless specified by the user as a config option) is assumed to
    # be the exact same name as the tag we're patching to, without the "-hotfix"
    # suffix.
    from_cmd = "cat $(location :to_tag) | sed -e 's|-hotfix[0-9]*$||' > $OUT"
    if patch_from:
      from_cmd = "echo {} > $OUT".format(patch_from)
    native.genrule(
        name="from_tag",
        cmd=from_cmd + notempty_cmd,
        out="from_tag",
        cacheable=False,
    )

    # form patch
    native.genrule(
        name="patches",
        cmd="""mkdir -p $OUT
            HOME=/dev/null git format-patch -k `cat $(location :from_tag)`..`cat $(location :to_tag)` -o $OUT/
            export hotfix=`cat $(location :hotfix)`
            cat `HOME=/dev/null git rev-parse --show-toplevel`/facebook/9999-Dummy-patch-to-bump-hotfix-version.patch.template | envsubst > $OUT/9999-Dummy-patch-to-bump-hotfix-version.patch
        """,
        out="patches",
        cacheable=False,
    )
    # download published rpms for baseline
    native.genrule(
        name="kernel-devel-klp",
        cmd="mkdir -p $OUT && kernelctl download --devel --out-dir $OUT `cat $(location :baseline-rpm-version)` && mv $OUT/*.rpm $OUT/kernel-devel.rpm",
        out="kernel-devel-klp",
        cacheable=False,
    )
    native.genrule(
        name="kernel-bin-klp",
        cmd="mkdir -p $OUT && kernelctl download --kernel --out-dir $OUT `cat $(location :baseline-rpm-version)` && mv $OUT/*.rpm $OUT/kernel-bin.rpm",
        out="kernel-bin-klp",
        cacheable=False,
    )
    bind_ros = [
        ("$(location :kernel-devel-klp)", "/tmp/kernel-devel"),
        ("$(location :kernel-bin-klp)", "/tmp/kernel-bin"),
        ("$(location :patches)", "/tmp/patches"),
        ("$(location :to_tag)", "/tmp/to_tag"),
        ("$(location :config)", "/tmp/config"),
        ("$(location :uname-klp)", "/tmp/uname"),
        ("$(location :hotfix)", "/tmp/hotfix"),
        ("$(location :baseline-rpm-version)", "/tmp/baseline_rpm_version")
    ]

    #checkout baseline
    native.genrule(
        name = "baseline-sources",
        cmd = """sudo rm -rf $OUT; mkdir -p $OUT
            HOME=/dev/null git clone -b `cat $(location :from_tag)` `HOME=/dev/null git rev-parse --show-toplevel` $OUT
            pushd $OUT
            make mrproper
            popd
        """,
        cacheable=False,
        out="baseline-sources",
    )

    #checkout target
    native.genrule(
        name = "target-sources",
        cmd = """sudo rm -rf $OUT; mkdir -p $OUT
            HOME=/dev/null git clone -b `cat $(location :to_tag)` `HOME=/dev/null git rev-parse --show-toplevel` $OUT
            pushd $OUT
            make mrproper
            popd
        """,
        cacheable = False,
        out = "target-sources",
    )

    #build the rpm version
    #more details on versioning available in buildinfo()
    #i don't have better idea on how to map between git tag/branch and rpm
    #v5.6-fbk13-rc1 -> 5.6.13-0_fbk13_rc1
    flavor_ver = "_%s" % flavor if flavor else ""
    label_ver = "_%s" % label if label else ""

    native.genrule(
        name = "baseline-rpm-version",
        cmd = """
            pushd $(location :baseline-sources)
            majorver=`make -s kernelversion EXTRAVERSION=`
            popd
            rpm_n=0
            fbkv=`cat $(location :from_tag) | sed -e 's|.*-\\(fbk[0-9]*\\).*|\\1|g'`
            rc=`cat $(location :from_tag) | grep -oE '\\b-rc[0-9]\\b$' | tr '-' '_'`
            flavor="%s"
            label="%s"
            echo "${majorver}-${rpm_n}_${fbkv}${flavor}${rc}${label}" > $OUT
        """ % (flavor_ver, label_ver),
        out = "baseline-rpm-version",
    )

    native.genrule(
      name = "target-image-url",
      cmd = """
          pushd $(location :target-sources)
          NO_BUCKD=1 ./facebook/build/buck query '//facebook/build:build-image' --output-attributes urls 0 | jq -r '.[][][]' > $OUT
          popd
      """,
      out = "target-image-url",
    )

    native.genrule(
        name = "target-image",
        cmd =  "curl `cat $(location :target-image-url)` -o $OUT",
        out = "target-image",
    )

    cfg_flavor = flavor
    if not flavor:
        cfg_flavor = "x86_64"

    if not cfg_flavor.startswith("x86_64"):
        cfg_flavor = "x86_64-%s" % cfg_flavor

    native.genrule(
      name = "config",
      cmd =  """
          pushd $(location :target-sources)
          cp `NO_BUCKD=1 ./facebook/build/buck build --show-output //facebook/config:%s | awk '{print $2}'` $OUT
          popd
      """ % (cfg_flavor),
      out = "config",
    )

    #uname of original kernel
    native.genrule(
        name = "uname-klp",
        cmd = "rpm -qp --queryformat '%{version}-%{release}' $(location :kernel-devel-klp)/kernel-devel.rpm > $OUT",
        out = "uname",
        cacheable=False,
    )

    train_data_args = ""
    compiler_args = ""

    if "clang" in cfg_flavor:
        native.genrule(
            name = "target-train-url",
            cmd = """
                pushd "$(location :target-sources)"
                NO_BUCKD=1 ./facebook/build/buck query '//facebook/build:clang-train-data' --output-attributes urls 0 | jq -r '.[][][]' > $OUT
                popd
            """,
            out = "target-train-url",
        )

        native.genrule(
            name = "target-train-data",
            cmd =  "curl `cat $(location :target-train-url)` -o $OUT",
            out = "target-train-data",
        )
        bind_ros.append(("$(location :target-train-data)", "/tmp/vmlinux.profdata_original"))
        train_data_args = "-p /tmp/vmlinux.profdata"
        compiler_args = "LLVM=1"


    #feed artifacts to kpatch-build in a container
    bind_rws = [(":baseline-sources", "/rw/linux"), ("$OUT", "/rw/output"), (":target-sources", "/rw/target")]
    container_genrule(
        name="klp-build",
        cmd="""
            rpm -ivh /tmp/kernel-bin/*.rpm /tmp/kernel-devel/*.rpm
            pushd /rw/target
            # prepare config for the target. It could be different from the baselines config
            cp /tmp/config .config
            make {compiler_args} O=/rw/target olddefconfig
            popd
            if [ -f /tmp/vmlinux.profdata_original ]; then
                # File path is part of the profile apparently
                # and its challenging to reproduce the build keeping all paths
                # completely the same.
                # In the future when someone will try to change the name of the file
                # for the baseline we may end up getting this broken.
                # But worst case we will just have to fix the pattern for sed.
                # sweet lord in heaven, fogive me for this
                pushd /tmp
                llvm-profdata merge vmlinux.profdata_original  --text --output=profile.txt
                sed "s|/ro/source/||g" -i profile.txt
                llvm-profdata merge profile.txt  --output=vmlinux.profdata
                popd
            fi
            kpatch-build {train_data_args} -s /rw/linux -c /rw/target/.config -v /boot/vmlinux* -o /rw/output -n klp_`cat /tmp/baseline_rpm_version`_`cat /tmp/hotfix` /tmp/patches/* || (cp /root/.kpatch/build.log /rw/output/ && exit 1)
        """.format(train_data_args = train_data_args, compiler_args = compiler_args),
        bind_ro=bind_ros,
        bind_rw=bind_rws,
        cacheable=False,
        image_override="$(location :target-image)",
    )
    # prepare packaging
    bind_ros.append(("$(location :klp-spec)", "/tmp/klp.spec"))
    bind_ros.append(("$(location :klp)", "/tmp/module"))
    native.genrule(
        name = "klp-spec",
        cmd = """
            pushd `HOME=/dev/null git rev-parse --show-toplevel`
            cp -a facebook/build/klp.spec $OUT
            popd
        """,
        out = "klp.spec",
        cacheable=False,
    )

    native.genrule(
        name = "klp",
        cmd = """
        if [ "{sign}" == "true" ]; then
          autograph_client.par kmod --sign-key {sign_key} --kernel-tree $(location :klp-build)
        fi
        cp -a $(location :klp-build)/* $OUT
        """.format(sign = sign, sign_key = sign_key),
        out = "klp.ko",
        cacheable=False,
    )


    container_genrule(
        name="klp-rpm",
        cmd="""
            cat /tmp/to_tag
            rpmbuild -ba /tmp/klp.spec --define "short_kernel_version `cat /tmp/baseline_rpm_version`" --define "rpm_kernel_version `cat /tmp/uname`" --define "module_path /tmp/module" --define "hf_name `cat /tmp/hotfix`"
            cp -vR /root/rpmbuild/RPMS/x86_64/*.rpm /rw/output/
        """,
        bind_ro=bind_ros,
        bind_rw=bind_rws,
        cacheable=False,
    )
