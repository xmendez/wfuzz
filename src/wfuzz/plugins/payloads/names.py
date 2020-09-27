from wfuzz.externals.moduleman.plugin import moduleman_plugin
from wfuzz.plugin_api.base import BasePayload
from wfuzz.fuzzobjects import FuzzWordType


@moduleman_plugin
class names(BasePayload):
    name = "names"
    author = (
        "Christian Martorella",
        "Adapted to newer versions Xavi Mendez (@xmendez)",
    )
    version = "0.1"
    description = ("ie. jon-smith",)
    summary = "Returns possible usernames by mixing the given words, separated by -, using known typical constructions."
    category = ["default"]
    priority = 99

    parameters = (("name", "", True, "Name and surname in the form of name-surname."),)

    default_parameter = "name"

    def __init__(self, params):
        BasePayload.__init__(self, params)

        possibleusernames = []
        name = ""
        llist = self.params["name"].split("-")

        for x in llist:
            if name == "":
                name = name + x
            else:
                name = name + " " + x

            if " " in name:
                parts = name.split()
                possibleusernames.append(parts[0])
                possibleusernames.append(parts[0] + "." + parts[1])
                possibleusernames.append(parts[0] + parts[1])
                possibleusernames.append(parts[0] + "." + parts[1][0])
                possibleusernames.append(parts[0][0] + "." + parts[1])
                possibleusernames.append(parts[0] + parts[1][0])
                possibleusernames.append(parts[0][0] + parts[1])
                str1 = ""
                str2 = ""
                str3 = ""
                str4 = ""
                for i in range(0, len(parts) - 1):
                    str1 = str1 + parts[i] + "."
                    str2 = str2 + parts[i]
                    str3 = str3 + parts[i][0] + "."
                    str4 = str4 + parts[i][0]
                str5 = str1 + parts[-1]
                str6 = str2 + parts[-1]
                str7 = str4 + parts[-1]
                str8 = str3 + parts[-1]
                str9 = str2 + parts[-1][0]
                str10 = str4 + parts[-1][0]
                possibleusernames.append(str5)
                possibleusernames.append(str6)
                possibleusernames.append(str7)
                possibleusernames.append(str8)
                possibleusernames.append(str9)
                possibleusernames.append(str10)
                possibleusernames.append(parts[-1])
                possibleusernames.append(parts[0] + "." + parts[-1])
                possibleusernames.append(parts[0] + parts[-1])
                possibleusernames.append(parts[0] + "." + parts[-1][0])
                possibleusernames.append(parts[0][0] + "." + parts[-1])
                possibleusernames.append(parts[0] + parts[-1][0])
                possibleusernames.append(parts[0][0] + parts[-1])
            else:
                possibleusernames.append(name)

            self.creatednames = possibleusernames
            self.__count = len(possibleusernames)

    def count(self):
        return self.__count

    def get_type(self):
        return FuzzWordType.WORD

    def get_next(self):
        if self.creatednames:
            payl = self.creatednames.pop()
            return payl
        else:
            raise StopIteration
