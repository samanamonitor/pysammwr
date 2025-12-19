from .protocol import WRProtocol
from .shell import WinRMShell
from .ciminstance import CimInstance
from .scheduledtasks import ScheduledTasks
from .posh import POSHCommand
from datetime import datetime
import json

import logging
log=logging.getLogger(__name__)


# TODO: add processing time to output


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
		log.debug("Started module with parameters:\n" + \
			f"   script_name={self.script_name}\n" + \
			f"   url_base={self.url_base}\n" + \
			f"   output_path={self.output_path}\n" + \
			f"   taskPath={self.taskPath}\n" + \
			f"   taskName={self.taskName}\n" + \
			f"   workdir={self.workdir}\n" + \
			f"   max_duration={self.max_duration}\n" +\
			f"   cleanup={self.cleanup}\n" + \
			f"   script={self.script}\n" + \
			f"   output_file={self.output_file}\n" + \
			f"   uri={self.uri}\n"
			)

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
		log.debug("Installed script %s.\nstdout=%s\nstderr=%s\ncode=%d", self.script, pc.stdout, pc.posh_error, pc.code)

	def prepare_script(self):
		script_instance=CimInstance("root/cimv2", "CIM_DataFile", protocol=self.p, Name=escape(self.script))
		try:
			script_instance.get()
			log.debug("Script %s found", self.script)
		except:
			log.debug("Script %s not found", self.script)
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
			log.debug("Task %s%s not found.", self.taskPath, self.taskName)
			# install Task
			act=self.st.NewScheduledTaskAction(None, Execute="powershell.exe", Argument=self.script, WorkingDirectory=self.workdir)
			task=self.st.RegisterScheduledTask(TaskName=self.taskName, TaskPath=self.taskPath, 
				Action=[act], User=self.p.username, Password=self.p.password)
			log.debug("Task %s%s created. %s", self.taskPath, self.taskName, task)
		else:
			task=ts_list[0]
		return task

	def get_output(self):
		output_instance=CimInstance("root/cimv2", "CIM_DataFile", protocol=self.p, Name=escape(self.output_file))
		of_list = list(output_instance)
		if len(of_list) > 0:
			log.debug("Outputfile %s found.", self.output_file)
			return of_list[0]
		else:
			log.debug("Outputfile %s not found.", self.output_file)
			return None

	def output_is_valid(self, output):
		if output is None:
			return False
		duration = datetime.now().timestamp() - output.LastModified.timestamp()
		if duration > self.max_duration:
			log.debug("Outputfile %s is too old.", self.output_file)
			return False
		log.debug("Outputfile %s is valid.", self.output_file)
		return True

	def __iter__(self):
		self.done = False
		self.script_instance = self.prepare_script()
		self.task = self.prepare_task()

		self.output = self.get_output()
		if not self.output_is_valid(self.output):
			self.st.StartScheduledTask(InputObject=self.task)
			log.debug("Task %s%s started.", self.taskPath, self.taskName)

		return self

	def __next__(self):
		if self.done:
			raise StopIteration

		with self.shell:
			out=self.shell.getfile(self.output_file)

		log.debug("Output read: %s", out)
		if self.cleanup:
			self.script_instance.Delete()
			if self.output is not None:
				self.output.Delete()
			self.st.UnregisterScheduledTask(InputObject=self.task)

		self.done = True
		try:
			data = json.loads(out[0])
		except:
			data = out[0]
		return data
