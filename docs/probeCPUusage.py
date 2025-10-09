from sammwr.wmi import WMIQuery
import os

username=os.environ.get('WR_USERNAME')
password=os.environ.get('WR_PASSWORD')
hostname=os.environ.get('WR_HOSTNAME')
q=WMIQuery(endpoint=f"http://{hostname}:5985/wsman", 
    username=username, 
    password=password, 
    class_name="Win32_PerfRawData_PerfProc_Process")

cpudata = {}
def newdata(procdata, cpudata, threshold=10):
    for i in procdata:
        p = cpudata.setdefault(str(i.IDProcess), {
            "Name": i.Name,
            "CPU": 0,
            "PercentProcessorTime": 0,
            "Timestamp_PerfTime": 0
        })
        dt = (i.Timestamp_PerfTime - p["Timestamp_PerfTime"])
        if dt != 0:
            p["CPU"] = (i.PercentProcessorTime - p["PercentProcessorTime"]) / dt * 100
        else:
            p["CPU"] = 0
        p["PercentProcessorTime"]  = i.PercentProcessorTime
        p["Timestamp_PerfTime"] = i.Timestamp_PerfTime
        if p["CPU"] > threshold:
            print(i.IDProcess, i.Name, int(p["CPU"]))

newdata(list(q), cpudata)

pid=3916
q1=WMIQuery(endpoint=f"http://{hostname}:5985/wsman", 
    username=username, 
    password=password, 
    wql=f"Select * from Win32_process where ProcessId={pid}")
proc=next(iter(q1))