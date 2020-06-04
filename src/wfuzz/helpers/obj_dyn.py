import functools
from .obj_dic import DotDict


allowed_fields = [
    "description",
    "nres",
    "code",
    "chars",
    "lines",
    "words",
    "md5",
    "l",
    "h",
    "w",
    "c",
    "history",
    "plugins",
    "url",
    "content",
    "history.url",
    "history.method",
    "history.scheme",
    "history.host",
    "history.content",
    "history.raw_content" "history.is_path",
    "history.pstrip",
    "history.cookies",
    "history.headers",
    "history.params",
    "r",
    "r.reqtime",
    "r.url",
    "r.method",
    "r.scheme",
    "r.host",
    "r.content",
    "r.raw_content" "r.is_path",
    "r.pstrip",
    "r.cookies.",
    "r.headers.",
    "r.params.",
]


def _check_allowed_field(attr):
    if [field for field in allowed_fields if attr.startswith(field)]:
        return True
    return False


def _get_alias(attr):
    attr_alias = {
        "l": "lines",
        "h": "chars",
        "w": "words",
        "c": "code",
        "r": "history",
    }

    if attr in attr_alias:
        return attr_alias[attr]

    return attr


def rsetattr(obj, attr, new_val, operation):
    # if not _check_allowed_field(attr):
    #    raise AttributeError("Unknown field {}".format(attr))

    pre, _, post = attr.rpartition(".")

    pre_post = None
    if len(attr.split(".")) > 3:
        pre_post = post
        pre, _, post = pre.rpartition(".")

    post = _get_alias(post)

    try:
        obj_to_set = rgetattr(obj, pre) if pre else obj
        prev_val = rgetattr(obj, attr)
        if pre_post is not None:
            prev_val = DotDict({pre_post: prev_val})

        if operation is not None:
            val = operation(prev_val, new_val)
        else:
            if isinstance(prev_val, DotDict):
                val = {k: new_val for k, v in prev_val.items()}
            else:
                val = new_val

        return setattr(obj_to_set, post, val)
    except AttributeError:
        raise AttributeError(
            "rsetattr: Can't set '{}' attribute of {}.".format(
                post, obj_to_set.__class__
            )
        )


def rgetattr(obj, attr, *args):
    def _getattr(obj, attr):
        attr = _get_alias(attr)
        try:
            return getattr(obj, attr, *args)
        except AttributeError:
            raise AttributeError(
                "rgetattr: Can't get '{}' attribute from '{}'.".format(
                    attr, obj.__class__
                )
            )

    # if not _check_allowed_field(attr):
    # raise AttributeError("Unknown field {}".format(attr))

    return functools.reduce(_getattr, [obj] + attr.split("."))
