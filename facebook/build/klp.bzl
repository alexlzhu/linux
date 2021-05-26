load("//facebook/config:defs.bzl", "config")
load("//facebook/build:container.bzl", "container_genrule")
load("//:defs.bzl", "buildinfo")
def klp(flavor=None, label=None):
    notempty_cmd = " && [ -s $OUT ] || exit 1"

    # overrides
    patch_to = native.read_config("klp", "patch_to", None)
    patch_from = native.read_config("klp", "patch_from", None)

    notempty_cmd = " && [ -s $OUT ] || exit 1"
    to_cmd = """git show-ref --tags -d | grep "^`git log --pretty="%h" -n1`" |
        awk -F '[ /]' '{print $NF}' | grep hotfix | head -n1 > $OUT"""
    if patch_to:
      to_cmd = "echo {} > $OUT".format(patch_to)

    from_cmd = "cat $(location :top_lvl_tag) | sed -e 's|-hotfix[0-9]*$||' > $OUT"
    if patch_from:
      from_cmd = "echo {} > $OUT".format(patch_from)

    # tag on the current HEAD
    native.genrule(
        name="top_lvl_tag",
        cmd=to_cmd + notempty_cmd,
        out="top_lvl_tag",
        cacheable=False,
    )

    native.genrule(
        name="hotfix",
        cmd="cat $(location :top_lvl_tag) | sed -e 's|.*\\(hotfix[0-9]*\\).*|\\1|g' > $OUT" + notempty_cmd,
        out="hotfix",
        cacheable=False,
    )

    # baseline for diff
    native.genrule(
        name="baseline",
        cmd=from_cmd + notempty_cmd,
        out="baseline",
        cacheable=False,
    )
    # form patch
    native.genrule(
        name="patches",
        cmd="mkdir -p $OUT ; git format-patch -k `cat $(location :baseline)`..`cat $(location :top_lvl_tag)` -o $OUT/",
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
    # build config for flavor
    config(
        name="config",
        flavor=flavor,
    )
    bind_ros = [
        ("$(location :kernel-devel-klp)", "/tmp/kernel-devel"),
        ("$(location :kernel-bin-klp)", "/tmp/kernel-bin"),
        ("$(location :patches)", "/tmp/patches"),
        ("$(location :top_lvl_tag)", "/tmp/top_lvl_tag"),
        ("$(location :config)", "/tmp/config"),
        ("$(location :uname-klp)", "/tmp/uname"),
        ("$(location :hotfix)", "/tmp/hotfix")
    ]

    #checkout baseline
    native.genrule(
        name = "baseline-sources",
        cmd = """sudo rm -rf $OUT; mkdir -p $OUT
            git clone -b `cat $(location :baseline)` `git rev-parse --show-toplevel` $OUT
            pushd $OUT
            make mrproper
            popd
        """,
        cacheable=False,
        out="baseline-sources",
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
            majorver=`make kernelversion EXTRAVERSION=`
            popd
            rpm_n=0
            fbkv=`cat $(location :baseline) | sed -e 's|.*-\\(fbk[0-9]*\\).*|\\1|g'`
            rc=`cat $(location :baseline) | grep -oE '\\b-rc[0-9]\\b$' | tr '-' '_'`
            flavor="%s"
            label="%s"
            echo "${majorver}-${rpm_n}_${fbkv}${flavor}${rc}${label}" > $OUT
        """ % (flavor_ver, label_ver),
        out="baseline-rpm-version",
    )


    #uname of original kernel
    native.genrule(
        name = "uname-klp",
        cmd = "rpm -qp --queryformat '%{version}-%{release}' $(location :kernel-devel-klp)/kernel-devel.rpm > $OUT",
        out = "uname",
        cacheable=False,
    )

    #feed artifacts to kpatch-build in a container
    bind_rws = [(":baseline-sources", "/rw/linux"), ("$OUT", "/rw/output")]
    container_genrule(
        name="klp-build",
        cmd="""
            rpm -ivh /tmp/kernel-bin/*.rpm /tmp/kernel-devel/*.rpm
            kpatch-build -s /rw/linux -c /tmp/config -v /boot/vmlinux* -o /rw/output -n klp_`cat /tmp/uname`_`cat /tmp/hotfix` /tmp/patches/* || (cp /root/.kpatch/build.log /rw/output/ && exit 1)
        """,
        bind_ro=bind_ros,
        bind_rw=bind_rws,
        cacheable=False,
    )
    # prepare packaging
    bind_ros.append(("$(location :klp-spec)", "/tmp/klp.spec"))
    bind_ros.append(("$(location :klp)", "/tmp/module"))
    native.genrule(
        name = "klp-spec",
        cmd = """
            pushd `git rev-parse --show-toplevel`
            cp -a facebook/build/klp.spec $OUT
            popd
        """,
        out = "klp.spec",
        cacheable=False,
    )

    sign = native.read_config('kernel', 'sign_mod', 'false')
    sign_key = native.read_config('kernel', 'sign_mod_key', 'autograph-test')

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
            cat /tmp/top_lvl_tag
            rpmbuild -ba /tmp/klp.spec --define "rpm_kernel_version `cat /tmp/uname`" --define "module_path /tmp/module" --define "hf_name `cat /tmp/hotfix`"
            cp -vR /root/rpmbuild/RPMS/x86_64/*.rpm /rw/output/
        """,
        bind_ro=bind_ros,
        bind_rw=bind_rws,
        cacheable=False,
    )
