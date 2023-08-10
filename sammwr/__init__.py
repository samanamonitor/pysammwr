__version__='0.0.4'

try:
    from .cmd import CMDCommand
    from .posh import POSHCommand
    from .wmi import WMIQuery
    from .shell import WinRMShell
    from .protocol import WRProtocol
    from .winrmcommand import WinRMCommand
except Exception as e:
    pass