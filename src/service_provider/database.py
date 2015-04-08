import dataset
from prettytable import PrettyTable

__author__ = 'danielevertsson'

ISSUER_COLUMN = "issuer"
LOCAL_USER_COLUMN = "local_user"
SUBECT_ID_COLUMN = "subject_id"

class PamDatabase():
    TABLE_NAME = 'pam'

    def __init__(self, dict_path):
        self.database = dataset.connect('sqlite:///' + dict_path)
        self.table = self.database[self.TABLE_NAME]

    def clear(self):
        self.table.drop()
        self.table = self.database[self.TABLE_NAME]

    def upsert(self, issuer, local_user, subject_id):
        row = {ISSUER_COLUMN: issuer,
               LOCAL_USER_COLUMN: local_user,
               SUBECT_ID_COLUMN: subject_id}
        self.table.upsert(row, [LOCAL_USER_COLUMN])

    def get_row(self, local_user):
        return self.table.find_one(local_user=local_user)

    def get_table_as_list(self):
        list = []
        rows = self.table.find(order_by=[SUBECT_ID_COLUMN])
        for row in rows:
            list.append([row[SUBECT_ID_COLUMN], row[LOCAL_USER_COLUMN], row[ISSUER_COLUMN]])
        return list

    def print_table(self):
        list =self.get_table_as_list()
        table = PrettyTable([SUBECT_ID_COLUMN, LOCAL_USER_COLUMN, ISSUER_COLUMN])
        table.padding_width = 1

        for row in list:
            list = []
            for element in row:
                if isinstance(element, int):
                    list.append(element)
                else:
                    list.append(element.encode('utf8'))
            table.add_row(list)
        print table