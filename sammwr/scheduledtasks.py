from .protocol import WRProtocol
from .ciminstance import CimInstance

class ScheduledTasks:
	def __init__(self, protocol=None, **kwargs):
		if isinstance(protocol, WRProtocol):
			self._protocol = protocol
		else:
			self._protocol = WRProtocol(**kwargs)

	def NewScheduledTaskAction(self, Id, Execute, **kwargs):
		kwargs['Execute'] = Execute
		if Id is not None:
			kwargs['Id'] = Id
		ci = CimInstance("Root/Microsoft/Windows/TaskScheduler", "PS_ScheduledTask", protocol=self._protocol)
		out = ci.run_method("NewActionByExec", **kwargs)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1]

	def NewScheduledTask(self, **kwargs):
		ci = CimInstance("Root/Microsoft/Windows/TaskScheduler", "PS_ScheduledTask", protocol=self._protocol)
		out = ci.run_method("New", **kwargs)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1]

	def RegisterScheduledTask(self, TaskName, TaskPath, InputObject=None, **kwargs):
		ci = CimInstance("Root/Microsoft/Windows/TaskScheduler", "PS_ScheduledTask", protocol=self._protocol)
		if isinstance(InputObject, CimInstance):
			out = ci.run_method("RegisterByObject", TaskName=TaskName, TaskPath=TaskPath, InputObject=InputObject)
		else:
			out = ci.run_method("RegisterByUser", TaskName=TaskName, TaskPath=TaskPath, **kwargs)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1]

	def GetInfoByName(self, TaskName, TaskPath):
		ci = CimInstance("Root/Microsoft/Windows/TaskScheduler", "PS_ScheduledTask", protocol=self._protocol)
		out = ci.run_method("GetInfoByName", TaskName=TaskName, TaskPath=TaskPath)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1]

	def GetScheduledTask(self, TaskName, TaskPath):
		st = CimInstance("Root/Microsoft/Windows/TaskScheduler", "MSFT_ScheduledTask", protocol=self._protocol, TaskName=TaskName, TaskPath=TaskPath)
		st.get()
		return st

	def UnregisterScheduledTask(self, TaskName=None, TaskPath=None, InputObject=None):
		if not isinstance(InputObject, CimInstance):
			InputObject = GetScheduledTask(self._protocol, TaskName, TaskPath)
		out = InputObject.delete(['TaskName', 'TaskPath'])
		return

