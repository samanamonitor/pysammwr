from .shell import WinRMShell, ExceptionWinRMShellNotConnected

class WinRMCommand:
    def __init__(self, shell, cmd, params=[], interactive=False):
        if not isinstance(shell, WinRMShell):
            raise TypeError("Can only accept WinRMShell.")
        self.shell = shell
        if not self.shell.connected:
            raise ExceptionWinRMShellNotConnected()
        self.cmd = cmd
        self.params = params
        self.data = {}
        self.command_id = None
        self.std_out = None
        self.std_err = None
        self.code = None
        self.done = None
        self.total_time = None
        self.error = False
        self.interactive = interactive

    def run(self):
        self.command_id = self.shell.run(self.cmd, self.params)

    def signal(self, s):
        self.signal_res = self.shell.signal(self.command_id, s)

    def close(self):
        if self.command_id is not None:
            command_id=self.command_id
            self.signal('terminate')
            self.command_id = None

    def send(self, data, expect_receive=True, end=False):
        if not self.interactive:
            return
        self.shell.send(self.command_id, data.encode('ascii'), expect_receive=False, end=end)
        if expect_receive:
            self.receive()

    def receive(self):
        if self.command_id is None:
            return None
        self.stdout, self.stderr, self.code, self.done, self.total_time = \
            self.shell.receive(self.command_id, interactive=self.interactive)
        if self.code != 0:
            self.error=True

    def exit(self):
        if not self.interactive:
            raise Exception("This is not an interactive session. Cannot exit")
        self.send_data = self.shell.send(self.command_id, 'exit\r\n', end=True)

    def __str__(self):
        return self.command_id

    def __enter__(self):
        self.shell.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.shell.close()
