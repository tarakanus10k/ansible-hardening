"""Edit literal GRUB kernel arguments without evaluating shell code."""
import re

_ASSIGNMENT = re.compile(
    r"""^([ \t]*(?:export[ \t]+)?GRUB_CMDLINE_LINUX(?:_DEFAULT|_RECOVERY)?=)(["'])([^\r\n]*?)\2([ \t]*(?:[ \t]#.*)?)$""",
    re.MULTILINE,
)
_ARGUMENT = re.compile(r"(?<![^ \t])apparmor=0(?:[ \t]+|(?=$))")
_BARE_DISABLED = re.compile(
    r"^([ \t]*(?:export[ \t]+)?GRUB_CMDLINE_LINUX(?:_DEFAULT|_RECOVERY)?=)apparmor=0([ \t]*(?:[ \t]#.*)?)$",
    re.MULTILINE,
)


def enable_apparmor(source):
    def edit(match):
        prefix, quote, value, suffix = match.groups()
        return prefix + quote + _ARGUMENT.sub("", value) + quote + suffix

    return _BARE_DISABLED.sub(r'\g<1>""\g<2>', _ASSIGNMENT.sub(edit, source))


class FilterModule:
    def filters(self):
        return {"cis_grub_apparmor_enabled": enable_apparmor}
