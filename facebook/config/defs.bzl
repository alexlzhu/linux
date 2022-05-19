load(":debug.td.bzl", "COMMON_DEBUG_OPTS", "DEBUG_OPTIONS_DEF")
load(":flavors.td.bzl", "FLAVORS_DEF")

# TODO(vmagro): we should probably follow the fs_image and others style of
# exporting a `struct` in each .bzl file that contains just the members we want
# exported
DEBUG_OPTIONS = DEBUG_OPTIONS_DEF
FLAVORS = FLAVORS_DEF

SELFTESTS = [ "livepatch", "vm" ]

def config_name(arch, flavor = None, debug = None, selftests = False):
    name = arch
    if flavor and flavor not in FLAVORS + ["lol2"]:
        fail(msg = "{} not an allowed flavor {}".format(flavor, FLAVORS), attr = "flavor")
    if debug and debug not in DEBUG_OPTIONS:
        fail(
            msg = "{} not an allowed debug option {}".format(debug, DEBUG_OPTIONS),
            attr = "debug",
        )
    name += "-" + flavor if flavor else ""
    name += "-" + debug if debug else ""
    name += "-selftests" if selftests else ""
    return name

def gen_config(name = None, flavor = None, debug = None, selftests = False):
    arch = "x86_64"
    if not name:
        name = config_name(arch, flavor, debug, selftests)
    elif selftests:
        name += "-selftests"
    flavor = "" if not flavor else flavor
    # without debug option
    if not debug:
        selftests_cmd = ""
        if selftests:
            selftests_cmd = "&& $(exe //facebook/scripts:selftestsconfig) {} >> .config".format(' '.join(SELFTESTS))
        native.genrule(
            name = name,
            cmd = "mkdir facebook && cp -R $(location //facebook/config:files) facebook/config && " +
                  "$(exe //facebook/scripts:prepareconfig) {} {}".format(arch, flavor) +
                  selftests_cmd + "&& mv .config $OUT",
            out = "config",
            type = "config",
            visibility = ["PUBLIC"],
        )
    else:
        # the debug opt genrule depends on the config without the debug option
        # (debug opt just adds another line to the config)
        without_debug = name.replace("-" + debug, "")
        selftests_cmd = ""
        if selftests:
          without_debug = without_debug.replace("-selftests", "")
          selftests_cmd = "&& $(exe //facebook/scripts:selftestsconfig) {} >> $OUT".format(' '.join(SELFTESTS))
        native.genrule(
            name = name,
            cmd = "cat $(location :{}) <(echo '{}') > $OUT {}".format(
                without_debug,
                DEBUG_OPTIONS[debug] + "\n" + COMMON_DEBUG_OPTS,
                selftests_cmd
            ),
            out = "config",
            type = "config",
            visibility = ["PUBLIC"],
        )

def config(name = None, flavor = None, debug = None):
    """
    Generate targets that will create the .config file used to configure the
    kernel at build time. Two sets of config targts are created:
    - Targets for regular kernel builds. That is, targets for the specified
      name, flavor, and debug options.
    - Targets that specifically enable kernel selftests. These targets provide
      exactly the same configurations as the regular targets, but also include
      whatever configurations are required in order to run selftests.
    """
    gen_config(name=name, flavor=flavor, debug=debug, selftests=False)
    gen_config(name=name, flavor=flavor, debug=debug, selftests=True)
