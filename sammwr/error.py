
class WRError(Exception):
    def __init__(self):
        super().__init__(self.args[0])
    code = 500
    @property
    def response_text(self):
        return self.args[1]

    @property
    def fault_data(self):
        return self.args[2]
    
    @property
    def fault_detail(self):
        return self.args[3]
