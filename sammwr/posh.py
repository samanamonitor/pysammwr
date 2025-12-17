from .winrmcommand import WinRMCommand
from .shell import WinRMShell
from base64 import b64encode
import xml.etree.ElementTree as ET
from time import time

class POSHCommand(WinRMCommand):
    def __init__(self, shell=None, scriptline=None, scriptfile=None, **kwargs):
        if not isinstance(shell, WinRMShell):
            shell = WinRMShell(**kwargs)
        super().__init__(shell, "")
        self.scriptfile=scriptfile
        self.scriptline=scriptline
        self.posh_error=''

    def run(self):
        script = None
        if self.scriptfile is not None:
            with open(self.scriptfile, "r") as f:
                script = "$ProgressPreference = 'SilentlyContinue';" + f.read()
        elif self.scriptline is not None:
            script = "$ProgressPreference='SilentlyContinue'; " + self.scriptline

        if script is not None:
            self.interactive = False
            encoded_ps = b64encode(script.encode('utf_16_le')).decode('ascii')
            params = [ '-encodedcommand', encoded_ps ]
        else:
            self.interactive = True
            params = []

        self.command_id = self.shell.run('powershell.exe', params)
        self.receive()
        self.decode_posh_error()

    def decode_posh_error(self):
        if len(self.stderr) == 0:
            return
        if self.stderr[0] == '#':
            temp = self.stderr.split('\n', 1)
            if len(temp) < 2:
                return
        try:
            root = ET.fromstring(temp[1])
        except ET.ParseError:
            return
        ns={ 'ps':root.tag.split('}')[0].split('{')[1] }
        self.posh_error = ""
        error = False
        for tag in root.findall('./ps:S', ns):
            t = tag.get('S')
            if t == 'Error':
                self.error = True
            self.posh_error += "%s : %s" % (t, tag.text.replace("_x000D__x000A_", "\n"))

    def __repr__(self):
        return "<%s interactive=%s code=%d error=%s std_out_bytes=%d std_err_bytes=%d>" % \
            (self.__class__.__name__, self.interactive,
                self.code, self.error,
                len(self.std_out), len(self.stderr))

class UploadFile:
    def __init__(self, script, base_url, local_path, ignore_cert=True, **kwargs):
        self.fullscript=f'''
            $script='{script}'
            $path='{local_path}'
            $uri='{base_url}/{script}'
            $ignore_cert='{"$true" if ignore_cert else "$false"}'
            $a=New-Item -Path $path -ItemType 'Directory' -Force
            if (-not $?) {{ exit 1}} else {{exit 0}}
            if ($ignore_cert) {{
                [System.Net.ServicePointManager]::ServerCertificateValidationCallback = {{$true}}
            }}
            Invoke-WebRequest -Uri $uri -OutFile $path\\$script
            if (-not $?) {{ exit 1}} else {{exit 0}}
        '''
        self.ps=POSHCommand(scriptline=self.fullscript, **kwargs)
    def __iter__(self):
        self._done = False
        return self
    def __next__(self):
        if self._done:
            raise StopIteration
        _start=time()
        with self.ps:
            self.ps.run()
        duration=time() - _start
        self._done = True
        return {
            "up": 1 if self.ps.code == 0 else 0,
            "code": self.ps.code, 
            "stdout": self.ps.stdout, 
            "stderr": self.ps.posh_error,
            "duration": duration
        }

