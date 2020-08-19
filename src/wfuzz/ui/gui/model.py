from collections import namedtuple
import wx.dataview as dv

from wfuzz.filters.ppfilter import FuzzResFilter

Row = namedtuple("Row", "title colid width rtype field")


class GUIModel(dv.PyDataViewIndexListModel):
    def __init__(self, data=None):
        self.data = data if data is not None else []
        dv.PyDataViewIndexListModel.__init__(self, len(self.data))

        self.row_mapper = {
            0: Row(title="ID", colid=0, width=100, rtype="int", field="nres"),
            1: Row(title="Response", colid=1, width=100, rtype="int", field="code"),
            2: Row(title="Lines", colid=2, width=170, rtype="int", field="lines"),
            3: Row(title="Words", colid=3, width=170, rtype="int", field="words"),
            4: Row(title="Chars", colid=4, width=170, rtype="int", field="chars"),
            5: Row(
                title="Payload", colid=5, width=170, rtype="string", field="description"
            ),
        }

    def GetColumnType(self, col):
        return self.row_mapper[col].rtype

    def GetValueByRow(self, row, col):
        try:
            return self.data[row].get_field(self.row_mapper[col].field)
        except IndexError:
            return ""

    def GetColumnCount(self):
        return len(self.row_mapper)

    def GetCount(self):
        return len(self.data)

    # Called to check if non-standard attributes should be used in the
    # cell at (row, col)
    def GetAttrByRow(self, row, col, attr):
        # #self.log.write('GetAttrByRow: (%d, %d)' % (row, col))
        # if col == 3:
        #     attr.SetColour('blue')
        #     attr.SetBold(True)
        #     return True
        return False

    def Compare(self, item1, item2, col, ascending):
        if not ascending:  # swap sort order?
            item2, item1 = item1, item2
        row1 = self.GetRow(item1)
        row2 = self.GetRow(item2)

        value1 = self.GetValueByRow(row1, col)
        value2 = self.GetValueByRow(row2, col)
        if self.row_mapper[col].rtype == "int":
            value1 = int(value1)
            value2 = int(value2)

        return (value1 > value2) - (value1 < value2)

    def DeleteRows(self, rows):
        # make a copy since we'll be sorting(mutating) the list
        rows = list(rows)
        # use reverse order so the indexes don't change as we remove items
        rows.sort(reverse=True)

        for row in rows:
            # remove it from our data structure
            del self.data[row]
            # notify the view(s) using this model that it has been removed
            self.RowDeleted(row)

    def AddRow(self, value):
        self.data.append(value)
        self.RowAppended()

    def Clear(self):
        self.data = []
        self.Cleared()

    def DeleteRows_by_filter(self, filter_string):
        ffilter = FuzzResFilter(filter_string=filter_string)

        for row, item in reversed(list(enumerate(self.data))):
            if ffilter.is_visible(item):
                del self.data[row]
                self.RowDeleted(row)
