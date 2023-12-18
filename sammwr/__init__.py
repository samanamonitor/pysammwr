__version__='0.0.8'

try:
    from .cmd import CMDCommand
    from .posh import POSHCommand
    from .wmi import WMIQuery
    from .shell import WinRMShell
    from .protocol import WRProtocol
    from .winrmcommand import WinRMCommand
    from .certificates import WRCertificates
except Exception as e:
    pass