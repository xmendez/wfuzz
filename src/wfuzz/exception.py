class FuzzException(Exception):
    pass


class FuzzExceptBadOptions(FuzzException):
    pass


class FuzzExceptNoPluginError(FuzzException):
    pass


class FuzzExceptPluginLoadError(FuzzException):
    pass


class FuzzExceptIncorrectFilter(FuzzException):
    pass


class FuzzExceptBadAPI(FuzzException):
    pass


class FuzzExceptInternalError(FuzzException):
    pass


class FuzzExceptBadFile(FuzzException):
    pass


class FuzzExceptBadInstall(FuzzException):
    pass


class FuzzExceptBadRecipe(FuzzException):
    pass


class FuzzExceptMissingAPIKey(FuzzException):
    pass


class FuzzExceptPluginBadParams(FuzzException):
    pass


class FuzzExceptResourceParseError(FuzzException):
    pass


class FuzzExceptPluginError(FuzzException):
    pass


class FuzzExceptNetError(FuzzException):
    pass
