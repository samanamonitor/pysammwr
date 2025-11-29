from .protocol import WRProtocol
from .ciminstance import CimInstance
from enum import Enum

class At(Enum):
	Once     = "NewTriggerByOnce"
	Daily    = "NewTriggerByDaily"
	Weekly   = "NewTriggerByWeekly"
	AtStartup= "NewTriggerByStartup"
	AtLogon  = "NewTriggerByLogon"

class ScheduledTasks:
	def __init__(self, protocol=None, **kwargs):
		if isinstance(protocol, WRProtocol):
			self._protocol = protocol
		else:
			self._protocol = WRProtocol(**kwargs)
		self.ci = CimInstance("Root/Microsoft/Windows/TaskScheduler", "PS_ScheduledTask", protocol=self._protocol)

	def DisableScheduledTask(self, TaskName=None, TaskPath=None, InputObject=None):
		if isinstance(InputObject, CimInstance):
			out = self.ci.DisableByObject(InputObject=InputObject)
		else:
			out = self.ci.DisableByName(TaskName=TaskName, TaskPath=TaskPath)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1].get("cmdletOutput")

	def EnableScheduledTask(self, TaskName=None, TaskPath=None, InputObject=None):
		if isinstance(InputObject, CimInstance):
			out = self.ci.EnableByObject(InputObject=InputObject)
		else:
			out = self.ci.EnableByName(TaskName=TaskName, TaskPath=TaskPath)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1].get("cmdletOutput")

	def ExportScheduledTask(self, TaskName=None, TaskPath=None, InputObject=None):
		if isinstance(InputObject, CimInstance):
			out = self.ci.ExportByObject(InputObject=InputObject)
		else:
			out = self.ci.ExportByName(TaskName=TaskName, TaskPath=TaskPath)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1].get("cmdletOutput")

	def GetClusteredScheduledTask(self, *args, **kwargs):
		raise Exception("Not Implemented")

	def GetScheduledTask(self, TaskName=None, TaskPath=None, InputObject=None):
		st = CimInstance("Root/Microsoft/Windows/TaskScheduler", "MSFT_ScheduledTask", protocol=self._protocol, TaskName=TaskName, TaskPath=TaskPath)
		st.get()
		return st

	def GetScheduledTaskInfo(self, TaskName=None, TaskPath=None, InputObject=None):
		if isinstance(InputObject, CimInstance):
			out = self.ci.GetInfoByObject(InputObject=InputObject)
		else:
			out = self.ci.GetInfoByName(TaskName=TaskName, TaskPath=TaskPath)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1].get("cmdletOutput")

	def NewScheduledTask(self, **kwargs):
		out = self.ci.New(**kwargs)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1].get("cmdletOutput")

	def NewScheduledTaskAction(self, Id, Execute, **kwargs):
		kwargs['Execute'] = Execute
		if Id is not None:
			kwargs['Id'] = Id
		out = self.ci.NewActionByExec(**kwargs)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1].get("cmdletOutput")

	def NewScheduledTaskPrincipal(self, **kwargs):
		if "GroupId" in kwargs:
			out = self.ci.NewPrincipalByGroup(**kwargs)
		else:
			out = self.ci.NewPrincipalByUser(**kwargs)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1].get("cmdletOutput")

	def NewScheduledTaskSettingsSet(self, **kwargs):
		out = self.ci.NewSettings(**kwargs)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1].get("cmdletOutput")

	def NewScheduledTaskTrigger(self, at, **kwargs):
		if not isinstance(at, At):
			raise TypeError("Parameter at must be of type At(Enum)")
		out = self.ci.run_method(at.value, **kwargs)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1].get("cmdletOutput")

	def RegisterScheduledTask(self, TaskName, TaskPath, InputObject=None, **kwargs):
		if isinstance(InputObject, CimInstance):
			out = self.ci.RegisterByObject(TaskName=TaskName, TaskPath=TaskPath, InputObject=InputObject)
		else:
			out = self.ci.RegisterByUser(TaskName=TaskName, TaskPath=TaskPath, **kwargs)
		if out[0] != 0:
			raise Exception("Unknown. Could not create CimInstance")
		return out[1].get("cmdletOutput")

	def UnregisterScheduledTask(self, TaskName=None, TaskPath=None, InputObject=None):
		if not isinstance(InputObject, CimInstance):
			InputObject = self.GetScheduledTask(TaskName, TaskPath)
		out = InputObject.delete()
		return

