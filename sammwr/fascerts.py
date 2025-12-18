from .protocol import WRProtocol
from .shell import WinRMShell
from .ciminstance import CimInstance
from .scheduledtasks import ScheduledTasks
from .posh import POSHCommand
from datetime import datetime
import json

escape = lambda s : "".join([ i if i != '\\' else i+i for i in s ])

class FasCerts:
	def __init__(self, script_name, url_base, output_path, workdir="c:\\SamanaStore", taskName="SAMM_FAS_CERT", taskPath='\\', max_duration=86400, cleanup=False, protocol=None, **kwargs):
		if isinstance(protocol, WRProtocol):
			self.p = protocol
		else:
			self.p = WRProtocol(**kwargs)
		self.script_name=script_name
		self.url_base=url_base
		self.output_path = output_path
		self.taskName=taskName
		self.taskPath=taskPath
		self.workdir=workdir
		self.max_duration=max_duration # 24 hours
		self.cleanup=cleanup

		self.script=self.workdir + "\\" + self.script_name
		self.output_file=self.workdir + "\\" + self.output_path
		self.uri=self.url_base + self.script_name
		self.st=ScheduledTasks(protocol=self.p)
		self.shell=WinRMShell(protocol=self.p)
		self.retry = False
		if self.p.transport.auth_method != "ntlm":
			raise Exception("This module can only be used with 'ntlm' transport")

	def install_script(self):
		script=f'''
		$directoryPath='{self.workdir}'
		$uri='{self.uri}'
		$dest='{self.script}'
		if (-not (Test-Path $directoryPath)) {{
			$a = New-Item -ItemType Directory -Path $directoryPath
		}}
		Invoke-WebRequest -Uri $uri -OutFile $dest
		if (-not ($?)) {{
			exit 1
		}}
		exit 0
		'''
		pc=POSHCommand(shell=self.shell, scriptline=script)
		with pc:
			pc.run()
		if pc.code != 0:
			raise Exception("Error executing install script." + pc.posh_error)

	def prepare_script(self):
		script_instance=CimInstance("root/cimv2", "CIM_DataFile", protocol=self.p, Name=escape(self.script))
		try:
			script_instance.get()
		except:
			if self.retry:
				raise Exception("Too many retries.")
			self.retry = True
			self.install_script()
			return self.prepare_script()
		self.retry = False
		return script_instance

	def prepare_task(self):
		ts=self.st.GetScheduledTask(TaskName=self.taskName, TaskPath=escape(self.taskPath))
		ts_list=list(ts)
		if len(ts_list) == 0:
			# install Task
			act=self.st.NewScheduledTaskAction(None, Execute="powershell.exe", Argument=self.script, WorkingDirectory=self.workdir)
			task=self.st.RegisterScheduledTask(TaskName=self.taskName, TaskPath=self.taskPath, 
				Action=[act], User=self.p.username, Password=self.p.password)
		else:
			task=ts_list[0]
		return task

	def get_output(self):
		output_instance=CimInstance("root/cimv2", "CIM_DataFile", protocol=self.p, Name=escape(self.output_file))
		of_list = list(output_instance)
		if len(of_list) > 0:
			return of_list[0]
		else:
			return None

	def output_is_valid(self, output):
		if output is None:
			return False
		duration = datetime.now().timestamp() - output.LastModified.timestamp()
		if duration > self.max_duration:
			return False
		else:
			return False
		return True

	def __iter__(self):
		self.done = False
		self.script_instance = self.prepare_script()
		self.task = self.prepare_task()

		self.output = self.get_output()
		if self.output_is_valid(self.output):
			st.StartScheduledTask(InputObject=self.task)

		return self

	def __next__(self):
		if self.done:
			raise StopIteration

		with self.shell:
			out=self.shell.getfile(self.output_file)

		if self.cleanup:
			self.script_instance.Delete()
			if self.output is not None:
				self.output.Delete()
			self.st.UnregisterScheduledTask(InputObject=self.task)

		self.done = True
		return out



