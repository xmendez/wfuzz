# Python 2 and 3 (after ``pip install configparser``):
try:
    from configparser import ConfigParser
except ImportError:
    import ConfigParser
import os
import sys


class SettingsBase:
    """
    Contains application settings. uses a ConfigParser
    """

    def __init__(self, save=False):
        self.cparser = ConfigParser()

        self.set_all(self.set_defaults())
        self.filename = os.path.join(
            self._path_to_program_dir(), self.get_config_file()
        )
        self.cparser.read(self.filename)

    # Base members should implement

    def get_config_file(self):
        """Returns the name of the file where the config is saved."""
        raise NotImplementedError

    def set_defaults(self):
        """
        Returns a dictionary with the default settings in the form of
        { \
                Section: [ \
                    ("setting_x", '5'),
                    ...
                    ("setting_y", '5'),
                ],
        ...
        }
        """
        raise NotImplementedError

    def has_option(self, section, setting):
        return self.cparser.has_option(section, setting)

    def set(self, section, setting, value):
        self.cparser.set(section, setting, value)

    def get(self, section, setting):
        value = self.cparser.get(section, setting)
        return value

    def get_section(self, section):
        return self.cparser.items(section)

    def get_options(self, section):
        return self.cparser.options(section)

    def get_sections(self):
        return self.cparser.sections()

    def get_all(self):
        sett = {}

        # dump entire config file
        for section in self.cparser.sections():
            for option in self.cparser.options(section):
                if section not in sett:
                    sett[section] = []
                sett[section].append((option, self.cparser.get(section, option)))

        return sett

    def set_all(self, sett):
        self.cparser = ConfigParser()
        for section, settings in sett.items():
            self.cparser.add_section(section)
            for key, value in settings:
                self.cparser.set(section, key, value)

    def save(self):
        try:
            with open(self.filename, "w") as iniFile:
                self.cparser.write(iniFile)
        except Exception:
            return False
        return True

    def _path_to_program_dir(self):
        """
        Returns path to program directory
        """
        path = sys.argv[0]

        if not os.path.isdir(path):
            path = os.path.dirname(path)

        if not path:
            return "."

        return path
