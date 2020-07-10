load("@builtins//:test_utils.td.bzl", "true")
load("@builtins//:schedule_type.td.bzl", "schedule_type_is")
load("//config:debug.td.bzl", "DEBUG_OPTIONS_DEF")
load("//config:flavors.td.bzl", "FLAVORS_DEF")

td_rule(
    name = "lint",
    predicate = schedule_type_is("diff"),
    output = output.sandcastle(
        {
            "alias": "lint",
            "command": "SandcastleKernelLintCommand",
            "args": {"async_lint": True},
            "description": "checkpatch.pl lint",
        },
    ),
)

def build(alias, do_kerneltest, notify, tags = None, priority = None, modules = True, **kwargs):
    args = {
        "build_only": not do_kerneltest,
        # we don't need fbcode to build the kernel, only to build tests, which
        # will happen in separate sandcastle jobs
        "disable_secondary_checkouts": True,
        # don't notify builder on diffs
        "notify": notify,
        "build_modules": modules,
    }
    args.update(kwargs)
    if not tags:
        tags = []
    tags = ["kernel", "linux-kernel", "kernel-contbuild"] + tags
    return output.sandcastle(
        {
            "alias": alias,
            "command": "SandcastleKernelBuildCommand",
            "args": args,
            "oncall": "kernel",
            "retries": 1,
            "tags": tags,
            "priority": priority,
        },
    )

td_rule(
    name = "linux-kernel-x86_64",
    predicate = schedule_type_is("diff"),
    # don't notify on diff builds
    output = build(
        alias = "linux-kernel-x86_64",
        do_kerneltest = True,
        notify = False,
        tags = ["diff"],
    ),
)

td_rule(
    name = "linux-kernel-x86_64",
    predicate = schedule_type_is("adhoc"),
    # adhoc builds are manually requested, so default to notifying when done
    output = build(
        alias = "linux-kernel-x86_64",
        do_kerneltest = True,
        notify = True,
        tags = ["adhoc"],
    ),
)

td_rule(
    name = "linux-kernel-x86_64",
    predicate = schedule_type_is("continuous"),
    output = build(
        alias = "linux-kernel-x86_64",
        do_kerneltest = True,
        notify = False,
    ),
)

[
    (
        td_rule(
            name = "linux-kernel-x86_64-{}".format(flavor),
            predicate = schedule_type_is("diff"),
            output = build(
                alias = "linux-kernel-x86_64-{}".format(flavor),
                do_kerneltest = False,
                notify = False,
                flavor = flavor,
                tags = ["diff"],
            ),
        ),
        td_rule(
            name = "linux-kernel-x86_64-{}".format(flavor),
            predicate = schedule_type_is("adhoc"),
            output = build(
                alias = "linux-kernel-x86_64-{}".format(flavor),
                do_kerneltest = False,
                notify = True,
                flavor = flavor,
                tags = ["adhoc"],
            ),
        ),
        td_rule(
            name = "linux-kernel-x86_64-{}".format(flavor),
            predicate = schedule_type_is("continuous"),
            output = build(
                alias = "linux-kernel-x86_64-{}".format(flavor),
                do_kerneltest = False,
                notify = False,
                flavor = flavor,
            ),
        ),
    )
    for flavor in FLAVORS_DEF
]

[
    td_rule(
        name = "linux-kernel-x86_64-{}".format(debug.lower()),
        predicate = schedule_type_is("continuous"),
        output = build(
            alias = "linux-kernel-x86_64-{}".format(debug.lower()),
            do_kerneltest = True,
            notify = False,
            debug_option = debug,
            modules = False,
            priority = 7,  # low
            tags = ["debug"],
        ),
    )
    for debug in DEBUG_OPTIONS_DEF
]
