from .protocol import WRProtocol
import xml.etree.ElementTree as ET

UPLOADMAX=800

class ExceptionWinRMShellNotConnected(Exception):
    pass

class ExceptionWinRMShellInvalidResponse(Exception):
    pass

class WinRMShell:
    def __init__(self, *args, protocol=None, cleanup=True, shell_id=None, **kwargs):
        if protocol is None:
            self.p = WRProtocol(*args, **kwargs)
        else:
            if not isinstance(protocol, WRProtocol):
                raise TypeError("Can only accept WRProtocol")
            self.p = protocol
        self.cleanup = cleanup
        self.data = {}
        self.shell_id = shell_id
        self.connected = False

    def open(self, shell_id=None):
        if shell_id is None:
            self.shell_id = self.p.open_shell()
        else:
            self.shell_id=shell_id

        self.connected = True

    def run(self, cmd, params=[]):
        if not self.connected:
            raise ExceptionWinRMShellNotConnected()
        return self.p.run_command(self.shell_id, cmd, params)

    def __str__(self):
        return self.shell_id

    def __repr__(self):
        return "<%s connected=%s shell_id=%s>" % \
            (self.__class__.__name__, self.connected, self.shell_id)

    def close(self):
        if not self.connected:
            raise ExceptionWinRMShellNotConnected()
        self.p.close_shell(self.shell_id)
        self.shell_id = None
        self.connected = False

    def signal(self, command_id, s):
        if not self.connected:
            raise ExceptionWinRMShellNotConnected()
        return self.p.signal(self.shell_id, command_id, s)

    def send(self, command_id, data, expect_receive=True, end=False, with_nl=True):
        if not self.connected:
            raise ExceptionWinRMShellNotConnected()
        self.send_res = self.p.send(self.shell_id, command_id, b"%s%s" \
            % (data, b"\r\n" if with_nl else b""), end)
        if expect_receive:
            return self.p.receive(self.shell_id, command_id)
        else:
            return None

    def list(self):
        resource_uri = 'http://schemas.microsoft.com/wbem/wsman/1/windows/shell'
        en = self.p.enumerate(resource_uri)
        root = ET.fromstring(en.decode('ascii'))
        ec = root.find('s:Body/wsen:EnumerateResponse/wsen:EnumerationContext', 
            self.p.xmlns)
        if ec is None:
            raise ExceptionWinRMShellInvalidResponse("Unable to retrieve the list of shells")
        ec = ec.text
        data = []
        while True:
            ec_data = self.p.pull(resource_uri, ec)
            pullresponse = ET.fromstring(ec_data)
            items = pullresponse.findall('s:Body/wsen:PullResponse/wsen:Items/', 
                self.p.xmlns)
            for item in items:
                sid = item.find('sh:ShellId', self.p.xmlns)
                if sid is not None:
                    sid = sid.text
                data += [ sid ]
            if pullresponse.find('s:Body/wsen:PullResponse/wsen:EndOfSequence', 
                    self.p.xmlns) is not None:
                break
            ec = pullresponse.find('s:Body/wsen:PullResponse/wsen:EnumerationContext', 
                self.p.xmlns)
            if ec is None:
                print("Invalid EnumerationContext.")
                break
            ec = ec.text
        return data

    def receive(self, command_id, interactive=False):
        if not self.connected:
            raise ExceptionWinRMShellNotConnected()
        stdin_data = ''
        stderr_data = ''
        total_time = 0
        while True:
            self._res=self.p.receive(self.shell_id, command_id)
            if interactive and self._res[3] == False:
                return self._res
            stdin_data += self._res[0].decode('ascii')
            stderr_data += self._res[1].decode('ascii')
            total_time += self._res[4]
            if self._res[3] == True:
                break
        return (stdin_data, stderr_data, self._res[2], self._res[3], total_time)

    def uploadfile(self, local_file, remote_file):
        out=None
        if not self.connected:
            raise ExceptionWinRMShellNotConnected()
        with open(local_file, "rb") as f:
            cmd_id=self.run("powershell.exe", ['-nologo'])
            self.send(cmd_id, b'@\'', expect_receive=False)
            while True:
                data=f.read(UPLOADMAX)
                self.send(cmd_id, data, with_nl=False, expect_receive=False)
                if len(data) < UPLOADMAX: break
            self.send(cmd_id, b'\r\n\'@ | Out-File %s' % (remote_file.encode('ascii')), expect_receive=False)
            self.send(cmd_id, b'', expect_receive=False)
            out=self.send(cmd_id, b'exit')
        return out

    def urlfile(self, url, remotefile):
        cmd="(new-object System.Net.WebClient).DownloadFile(\"%s\", \"%s\")" \
            % (url, remotefile)
        return self.posh(scriptline=cmd)

    def getfile(self, remotefile):
        if not self.connected:
            raise Exception("Not Connected")
        self.command_id = self.p.run_command(self.shell_id, 'type', [ remotefile ])
        return self.receive(self.command_id)

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
