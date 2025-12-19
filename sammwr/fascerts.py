from .protocol import WRProtocol
from .shell import WinRMShell
from .ciminstance import CimInstance
from .scheduledtasks import ScheduledTasks
from .posh import POSHCommand
from datetime import datetime
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from urllib import request
import json

import logging
log=logging.getLogger(__name__)

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
		self.uri=self.url_base + "/" + self.script_name
		self.st=ScheduledTasks(protocol=self.p)
		self.shell=WinRMShell(protocol=self.p)
		self.retry = False
		self.install_script_seconds = 0.0
		self.crl_verification_seconds = 0.0
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
		start=datetime.now().timestamp()
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
		self.install_script_seconds=datetime.now().timestamp() - start

	def prepare_script(self):
		start=datetime.now().timestamp()
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
		self.prepare_script_seconds=datetime.now().timestamp() - start
		return script_instance

	def prepare_task(self):
		start=datetime.now().timestamp()
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
		self.prepare_task_seconds=datetime.now().timestamp() - start
		return task

	def get_output(self):
		start=datetime.now().timestamp()
		output_instance=CimInstance("root/cimv2", "CIM_DataFile", protocol=self.p, Name=escape(self.output_file))
		of_list = list(output_instance)
		out=None
		if len(of_list) > 0:
			log.debug("Outputfile %s found.", self.output_file)
			out = of_list[0]
		else:
			log.debug("Outputfile %s not found.", self.output_file)
		self.get_output_seconds = datetime.now().timestamp() - start
		return out

	def output_is_valid(self, output):
		if output is None:
			return False
		duration = datetime.now().timestamp() - output.LastModified.timestamp()
		if duration > self.max_duration:
			log.debug("Outputfile %s is too old.", self.output_file)
			return False
		log.debug("Outputfile %s is valid.", self.output_file)
		return True

	def get_crl_expiration(self, pem_data):
		start = datetime.now().timestamp()
		if not isinstance(pem_data, bytes):
			return -1
		cert = x509.load_pem_x509_certificate(pem_data, default_backend())
		crl_dist = cert.extensions.get_extension_for_class(x509.extensions.CRLDistributionPoints)
		crl_data = None
		crl_strings = []
		for distribution_value in crl_dist.value:
			for name in distribution_value.full_name:
				crl_url = name.value
				crl_strings.append(crl_url)
				with request.urlopen(crl_url) as response:
					crl_data=response.read()
				if isinstance(b'', bytes) and len(crl_data) > 0:
					break
			if isinstance(b'', bytes) and len(crl_data) > 0:
				break

		if not isinstance(crl_data, bytes):
			raise TypeError("Unable to download CRL. %s", crl_strings)

		if crl_data[:5] == b'-----':
			crl = x509.load_pem_x509_crl(crl_data, backend=default_backend())
		else:
			crl = x509.load_der_x509_crl(crl_data, backend=default_backend())

		self.crl_verification_seconds = datetime.now().timestamp() - start
		return crl.next_update_utc.timestamp() - datetime.now().timestamp()

	def __iter__(self):
		self._process_start = datetime.now().timestamp()
		self.done = False
		self.script_instance = self.prepare_script()
		self.task = self.prepare_task()

		self.output = self.get_output()
		if not self.output_is_valid(self.output):
			self.st.StartScheduledTask(InputObject=self.task)
			log.debug("Task %s%s started.", self.taskPath, self.taskName)

		return self

	def __next__(self):
		start=datetime.now().timestamp()
		if self.done:
			raise StopIteration

		with self.shell:
			out=self.shell.getfile(self.output_file)

		self.get_output_data_seconds = datetime.now().timestamp() - start
		if self.cleanup:
			self.script_instance.Delete()
			if self.output is not None:
				self.output.Delete()
			self.st.UnregisterScheduledTask(InputObject=self.task)

		self.done = True
		try:
			data = json.loads(out[0])
		except:
			data = { "outstr": out[0]}

		data['install_script_seconds'] = self.install_script_seconds
		data['prepare_script_seconds'] = self.prepare_script_seconds
		data['prepare_task_seconds'] = self.prepare_task_seconds
		data['get_output_seconds'] = self.get_output_seconds
		data['get_output_data_seconds'] = self.get_output_data_seconds
		data['process_time_seconds'] = datetime.now().timestamp() - self._process_start

		server_cert = data.get('CurrentCertificate', {}).get('Certificate')
		crl_cert_check = data.get('UserCert', server_cert)
		try:
			data['crl_expiration_seconds'] = self.get_crl_expiration(crl_cert_check.encode('utf-8'))
		except Exception as e:
			log.error("Unable to get CRL information. %s", str(e))
			data['crl_expiration_seconds'] = -1
		data['crl_verification_seconds'] = self.crl_verification_seconds

		log.debug("Output: %s", data)

		return data
