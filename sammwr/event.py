from .wmi import WMIQuery
import time
import logging

log = logging.getLogger(__name__)

EVENT_ERROR = 1
EVENT_WARNING = 2
EVENT_INFORMATION = 3
EVENT_AUDIT_SUCCESS = 4
EVENT_AUDIT_FAILURE = 5

class CIMEvent:
    def __init__(self, max_events=50, max_seconds=600, logfile=None,
            event_type=None, *args, **kwargs):

        if not isinstance(logfile, str):
            raise TypeError("Invalid type for logfile. Must be str")

        self._max_events = max_events
        self._max_seconds = max_seconds
        self._logfile = logfile
        self._record_number = 0
        self._event_type = int(event_type)
        self._wql = "SELECT * FROM Win32_NTLogEvent WHERE TimeGenerated > '%s' and EventType <= %d and Logfile = '%s'" \
             % (self._get_time(), self._event_type, self._logfile)
        self._cim_query = WMIQuery(wql=self._wql, *args, **kwargs)

    def _get_time(self):
        ct = time.strptime(time.ctime(time.time() - self._max_seconds))
        timefilter = "%04d%02d%02d%02d%02d%02d.000-000" % (ct.tm_year, ct.tm_mon, ct.tm_mday, 
            ct.tm_hour, ct.tm_min, ct.tm_sec)
        return timefilter

    def __iter__(self):
        self._wql = "SELECT * FROM Win32_NTLogEvent WHERE TimeGenerated > '%s' and EventType <= %d and Logfile = '%s'" \
            % (self._get_time(), self._event_type, self._logfile)
        if self._record_number > 0:
            self._wql += " and RecordNumber > %s" % self._record_number
        self._cim_query._wql = self._wql
        self._iter = iter(self._cim_query)
        return self

    def __next__(self):
        data = next(self._iter)
        log.debug(data)
        if data.RecordNumber > self._record_number:
            self._record_number = data.RecordNumber
        if time.time() - data.TimeGenerated > self._max_seconds:
            self._cim_query.release()
            self._iter = None
            raise StopIteration
        if data.RecordNumber < (self._record_number - self._max_events):
            self._cim_query.release()
            self._iter = None
            raise StopIteration

        return data