load(":debug.td.bzl", "COMMON_DEBUG_OPTS", "DEBUG_OPTIONS_DEF")
load(":flavors.td.bzl", "FLAVORS_DEF")

# TODO(vmagro): we should probably follow the fs_image and others style of
# exporting a `struct` in each .bzl file that contains just the members we want
# exported
DEBUG_OPTIONS = DEBUG_OPTIONS_DEF
FLAVORS = FLAVORS_DEF

def config_name(arch, flavor = None, debug = None):
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
    return name

def config(name = None, flavor = None, debug = None):
    arch = "x86_64"
    if not name:
        name = config_name(arch, flavor, debug)
    flavor = "" if not flavor else flavor

    # without debug option
    if not debug:
        native.genrule(
            name = name,
            cmd = "mkdir facebook && cp -R $(location //facebook/config:files) facebook/config && " +
                  "$(exe //facebook/scripts:prepareconfig) {} {}".format(arch, flavor) +
                  "&& mv .config $OUT",
            out = "config",
            type = "config",
            visibility = ["PUBLIC"],
        )
    else:
        # the debug opt genrule depends on the config without the debug option
        # (debug opt just adds another line to the config)
        without_debug = name.replace("-" + debug, "")
        native.genrule(
            name = name,
            cmd = "cat $(location :{}) <(echo '{}') > $OUT".format(
                without_debug,
                DEBUG_OPTIONS[debug] + "\n" + COMMON_DEBUG_OPTS,
            ),
            out = "config",
            type = "config",
            visibility = ["PUBLIC"],
        )
