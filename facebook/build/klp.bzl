load("//facebook/config:defs.bzl", "config")
load("//facebook/build:container.bzl", "container_genrule")
load("//:defs.bzl", "buildinfo")
def klp(flavor=None):
    # tag on the current HEAD
    native.genrule(
        name="top_lvl_tag",
        cmd="""git show-ref --tags -d | grep "^`git log --pretty="%h" -n1`" |
            awk -F '[ /]' '{print $NF}' | grep hotfix | head -n1 > $OUT; [ -s $OUT ] || exit 1
        """,
        out="top_lvl_tag",
        cacheable=False,
    )
    native.genrule(
        name="hotfix",
        cmd="cat $(location :top_lvl_tag) | sed -e 's|.*\\(hotfix[0-9]\\).*|\\1|g' > $OUT; [ -s $OUT ] || exit 1",
        out="hotfix",
        cacheable=False,
    )
    # baseline for diff
    native.genrule(
        name="baseline",
        cmd="cat $(location :top_lvl_tag) | sed -e 's|-hotfix[0-9]*$||' > $OUT",
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
    info = buildinfo()
    baseline_version = "{}-{}_{}".format(info.kernelversion, info.rpm_number, info.fbk)
    if flavor:
      baseline_version = "{}_{}".format(baseline_version, flavor)
    native.genrule(
        name="kernel-devel-{}".format(baseline_version),
        cmd="mkdir -p $OUT && kernelctl download --devel --out-dir $OUT {} && mv $OUT/*.rpm $OUT/kernel-devel.rpm".format(baseline_version),
        out="kernel-devel",
        cacheable=False,
    )
    native.genrule(
        name="kernel-bin-{}".format(baseline_version),
        cmd="mkdir -p $OUT && kernelctl download --kernel --out-dir $OUT {} && mv $OUT/*.rpm $OUT/kernel-bin.rpm".format(baseline_version),
        out="kernel-bin",
        cacheable=False,
    )
    # build config for flavor
    config(
        name="config",
        flavor=flavor,
    )
    bind_ros = [
        ("$(location :kernel-devel-{})".format(baseline_version), "/tmp/kernel-devel"),
        ("$(location :kernel-bin-{})".format(baseline_version), "/tmp/kernel-bin"),
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

    #uname of original kernel
    native.genrule(
        name = "uname-klp",
        cmd = "rpm -qp --queryformat '%{version}-%{release}' $(location :kernel-devel-" + "{})/kernel-devel.rpm > $OUT".format(baseline_version),
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
    native.genrule(
        name="klp",
        cmd="cp $(location :klp-build)/* $OUT",
        out = "klp.ko",
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
