def template(
        name,
        src,
        variables = None,
        out = None,
        executable = False,
        **genrule_kwargs):
    """template renders a golang template as the output of the genrule"""
    if not out:
        out = name
    if not variables:
        variables = struct()
    post = ""
    if executable:
        post = "&& chmod +x $OUT"
    native.genrule(
        name = name,
        out = out,
        cmd = "$(exe //facebook:template) -template $(location {}) -vars '{}' > $OUT {}".format(src, variables.to_json(), post),
        executable = executable,
        **genrule_kwargs
    )
