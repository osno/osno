from os import listdir, remove
from os.path import basename, dirname, join
from re import match
from shutil import move, rmtree
from tempfile import mkdtemp
from threading import Thread, enumerate as tenumerate
from base64 import encodebytes
from json import loads
from time import sleep
from urllib.error import URLError
from urllib.parse import quote
from urllib.request import Request, urlopen
from json import loads
from Components.config import config
from Screens.MessageBox import MessageBox
from Tools.Notifications import AddNotificationWithID
from time import mktime, strftime, time, localtime
from enigma import eTimer

from os import path as ospath, remove, walk
import re
from enigma import eServiceReference, eDVBDB
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

autoClientModeTimer = None

supportfiles = ('lamedb', 'blacklist', 'whitelist', 'alternatives.')

e2path = "/etc/enigma2"

def autostart():
	global autoClientModeTimer
	print("[ClientModeScheduler][ClientModeautostart] AutoStart Enabled")
	if autoClientModeTimer is None:
		autoClientModeTimer = AutoClientModeTimer()


def getRemoteAddress():
	if config.clientmode.serverAddressType.value == "ip":
		return "%d.%d.%d.%d" % (config.clientmode.serverIP.value[0], config.clientmode.serverIP.value[1], config.clientmode.serverIP.value[2], config.clientmode.serverIP.value[3])
	else:
		return config.clientmode.serverDomain.value


class AutoClientModeTimer:
	instance = None

	def __init__(self):
		self.clientmodetimer = eTimer()
		self.clientmodetimer.callback.append(self.ClientModeonTimer)
		self.autostartscantimer = eTimer()
		self.autostartscantimer.callback.append(self.doautostartscan)
		self.clientmodeactivityTimer = eTimer()
		self.clientmodeactivityTimer.timeout.get().append(self.clientmodedatedelay)
		now = int(time())
		self.attempts = 0
		self.doautostartscan() # import at boot time

		global ClientModeTime
		if config.clientmode.enableSchedule.value:
			print("[ClientModeScheduler][AutoClientModeTimer] Schedule Enabled at ", strftime("%c", localtime(now)))
			if now > 1262304000:
				self.clientmodedate()
			else:
				print("[ClientModeScheduler][AutoClientModeTimer] Time not yet set.")
				ClientModeTime = 0
				self.clientmodeactivityTimer.start(36000)
		else:
			ClientModeTime = 0
			print("[ClientModeScheduler][AutoClientModeTimer] Schedule Disabled at", strftime("%c", localtime(now)))
			self.clientmodeactivityTimer.stop()

		assert AutoClientModeTimer.instance is None, "class AutoClientModeTimer is a singleton class and just one instance of this class is allowed!"
		AutoClientModeTimer.instance = self

	def __onClose(self):
		AutoClientModeTimer.instance = None

	def clientmodedatedelay(self):
		self.clientmodeactivityTimer.stop()
		self.clientmodedate()

	def getClientModeTime(self):
		backupclock = config.clientmode.scheduletime.value
		nowt = time()
		now = localtime(nowt)
		if config.clientmode.scheduleRepeatInterval.value.isdigit(): # contains wait time in minutes
			repeatIntervalMinutes = int(config.clientmode.scheduleRepeatInterval.value)
			return int(mktime((now.tm_year, now.tm_mon, now.tm_mday, now.tm_hour, now.tm_min + repeatIntervalMinutes, 0, now.tm_wday, now.tm_yday, now.tm_isdst)))
		return int(mktime((now.tm_year, now.tm_mon, now.tm_mday, backupclock[0], backupclock[1], 0, now.tm_wday, now.tm_yday, now.tm_isdst)))

	def clientmodedate(self, atLeast=0):
		self.clientmodetimer.stop()
		global ClientModeTime
		ClientModeTime = self.getClientModeTime()
		now = int(time())
		if ClientModeTime > 0:
			if ClientModeTime < now + atLeast:
				if config.clientmode.scheduleRepeatInterval.value.isdigit(): # contains wait time in minutes
					ClientModeTime = now + (60 * int(config.clientmode.scheduleRepeatInterval.value))
					while (int(ClientModeTime) - 30) < now:
						ClientModeTime += 60 * int(config.clientmode.scheduleRepeatInterval.value)
				elif config.clientmode.scheduleRepeatInterval.value == "daily":
					ClientModeTime += 24 * 3600
					while (int(ClientModeTime) - 30) < now:
						ClientModeTime += 24 * 3600
				elif config.clientmode.scheduleRepeatInterval.value == "weekly":
					ClientModeTime += 7 * 24 * 3600
					while (int(ClientModeTime) - 30) < now:
						ClientModeTime += 7 * 24 * 3600
				elif config.clientmode.scheduleRepeatInterval.value == "monthly":
					ClientModeTime += 30 * 24 * 3600
					while (int(ClientModeTime) - 30) < now:
						ClientModeTime += 30 * 24 * 3600
			next = ClientModeTime - now
			self.clientmodetimer.startLongTimer(next)
		else:
			ClientModeTime = -1
		print("[ClientModeScheduler][clientmodedate] Time set to", strftime("%c", localtime(ClientModeTime)), strftime("(now=%c)", localtime(now)))
		return ClientModeTime

	def backupstop(self):
		self.clientmodetimer.stop()

	def ClientModeonTimer(self):
		self.clientmodetimer.stop()
		now = int(time())
		wake = self.getClientModeTime()
		# If we're close enough, we're okay...
		atLeast = 0
		if wake - now < 60:
			atLeast = 60
			print("[ClientModeScheduler][ClientModeonTimer] onTimer occured at", strftime("%c", localtime(now)))
			self.doClientMode(True)
		self.clientmodedate(atLeast)

	def doClientMode(self, answer):
		self.autostartscantimer.stop()
		self.attempts = 0
		now = int(time())
		print("[ClientModeScheduler][doClientMode] Running ClientMode", strftime("%c", localtime(now)))
		self.autostartscantimer.start(100, 1)

	def doautostartscan(self):
		self.autostartscantimer.stop()
		if self.checkFTPconnection():
			self.attempts = 0
			ChannelsImporter()
		else:
			if self.attempts < 5:
				print("[ChannelsImporter] attempt %d failed. Retrying..." % (self.attempts + 1,))
				self.autostartscantimer.startLongTimer(10)
			self.attempts += 1

	def checkFTPconnection(self):
		print("[ChannelsImporter][checkFTPconnection] Testing FTP connection...")
		try:
			from ftplib import FTP
			ftp = FTP()
			ftp.set_pasv(config.clientmode.passive.value)
			ftp.connect(host=getRemoteAddress(), port=config.clientmode.serverFTPPort.value, timeout=5)
			result = ftp.login(user=config.clientmode.serverFTPusername.value, passwd=config.clientmode.serverFTPpassword.value)
			ftp.quit()
			if result.startswith("230"):
				print("[ChannelsImporter][checkFTPconnection] FTP connection success:", result)
				return True
			print("[ChannelsImporter][checkFTPconnection] FTP connection failure:", result)
			return False
		except Exception as err:
			print("[ChannelsImporter][checkFTPconnection] Error:", err)
			return False

	def doneConfiguring(self):
		now = int(time())
		if config.clientmode.enableSchedule.value:
			if autoClientModeTimer is not None:
				print("[ClientModeScheduler][doneConfiguring] Schedule Enabled at", strftime("%c", localtime(now)))
				autoClientModeTimer.clientmodedate()
		else:
			if autoClientModeTimer is not None:
				global ClientModeTime
				ClientModeTime = 0
				print("[ClientModeScheduler][doneConfiguring] Schedule Disabled at", strftime("%c", localtime(now)))
				autoClientModeTimer.backupstop()


class ImportChannels:

	def __init__(self):
		self.e2path = "/etc/enigma2"
		if config.usage.remote_fallback_enabled.value and config.usage.remote_fallback_import.value and config.usage.remote_fallback.value and not "ChannelsImport" in [x.name for x in tenumerate()]:
			self.header = None
			if config.usage.remote_fallback_enabled.value and config.usage.remote_fallback_import.value and config.usage.remote_fallback_import_url.value != "same" and config.usage.remote_fallback_import_url.value:
				self.url = config.usage.remote_fallback_import_url.value.rsplit(":", 1)[0]
			else:
				self.url = config.usage.remote_fallback.value.rsplit(":", 1)[0]
			if config.usage.remote_fallback_openwebif_customize.value:
				self.url = f"{self.url}:{config.usage.remote_fallback_openwebif_port.value}"
				if config.usage.remote_fallback_openwebif_userid.value and config.usage.remote_fallback_openwebif_password.value:
					self.header = "Basic %s" % encodebytes(("%s:%s" % (config.usage.remote_fallback_openwebif_userid.value, config.usage.remote_fallback_openwebif_password.value)).encode("UTF-8")).strip().decode()
			self.remote_fallback_import = config.usage.remote_fallback_import.value
			self.thread = Thread(target=self.threaded_function, name="ChannelsImport")
			self.thread.start()

	def getUrl(self, url, timeout=5):
		request = Request(url)
		if self.header:
			request.add_header("Authorization", self.header)
		try:
			result = urlopen(request, timeout=timeout)
		except URLError as e:
			if "[Errno -3]" in str(e.reason):
				print("[Import Channels] Network is not up yet, delay 5 seconds")
				# network not up yet
				sleep(5)
				return self.getUrl(url, timeout)
			print(f"[Import Channels] URLError {str(e)}")
			raise (e)
		return result

	def getTerrestrialUrl(self):
		url = config.usage.remote_fallback_dvb_t.value
		return url[:url.rfind(":")] if url else self.url

	def getFallbackSettings(self):
		result = self.getUrl(f"{self.getTerrestrialUrl()}/api/settings").read()
		if result:
			result = loads(result.decode("utf-8"))
			if result.get("result"):
				return {result["settings"][i][0]: result["settings"][i][1] for i in range(0, len(result["settings"]))}
		return {}

	def getFallbackSettingsValue(self, settings, e2settingname):
		# complete key lookup
		if e2settingname in settings:
			return settings[e2settingname]
		# partial key lookup
		for e2setting in settings:
			if e2settingname in e2setting:
				return settings[e2setting]
		return ""

	def getTerrestrialRegion(self, settings):
		description = ""
		descr = self.getFallbackSettingsValue(settings, ".terrestrial")
		if "Europe" in descr:
			description = "fallback DVB-T/T2 Europe"
		if "Australia" in descr:
			description = "fallback DVB-T/T2 Australia"
		config.usage.remote_fallback_dvbt_region.value = description

	"""
	Enumerate all the files that make up the bouquet system, either local or on a remote machine
	"""

	def ImportGetFilelist(self, remote=False, *files):
		result = []
		for file in files:
			# read the contents of the file
			try:
				if remote:
					try:
						content = self.getUrl(f"{self.url}/file?file={self.e2path}/{quote(file)}").readlines()
						content = map(lambda l: l.decode("utf-8", "replace"), content)
					except Exception as e:
						print(f"[Import Channels] Exception: {str(e)}")
						continue
				else:
					with open(f"{self.e2path}/{file}", "r") as f:
						content = f.readlines()
			except Exception as e:
				# for the moment just log and ignore
				print(f"[Import Channels] {str(e)}")
				continue

			# check the contents for more bouquet files
			for line in content:
#				print ("[Import Channels] %s" % line)
				# check if it contains another bouquet reference, first tv type then radio type
				r = match('#SERVICE 1:7:1:0:0:0:0:0:0:0:FROM BOUQUET "(.*)" ORDER BY bouquet', line) or match('#SERVICE 1:7:2:0:0:0:0:0:0:0:FROM BOUQUET "(.*)" ORDER BY bouquet', line)
				if r:
					# recurse
					result.extend(self.ImportGetFilelist(remote, r.group(1)))
			# add add the file itself
			result.append(file)

		# return the file list
		return result

	def threaded_function(self):
		settings = self.getFallbackSettings()
		self.getTerrestrialRegion(settings)
		self.tmp_dir = mkdtemp(prefix="ImportChannels_")

		if "epg" in self.remote_fallback_import:
			print("[Import Channels] Writing epg.dat file on server box")
			try:
				result = loads(self.getUrl(f"{self.url}/api/saveepg", timeout=30).read().decode("utf-8"))
				if "result" not in result and result["result"] == False:
					self.ImportChannelsDone(False, _("Error when writing epg.dat on the fallback receiver"))
			except Exception as e:
				print(f"[Import Channels] Exception: {str(e)}")
				self.ImportChannelsDone(False, _("Error when writing epg.dat on the fallback receiver"))
				return
			print("[Import Channels] Get EPG Location")
			try:
				epgdatfile = self.getFallbackSettingsValue(settings, "config.misc.epgcache_filename") or "/media/hdd/epg.dat"
				try:
					files = [file for file in loads(self.getUrl(f"{self.url}/file?dir={dirname(epgdatfile)}").read())["files"] if basename(file).startswith(basename(epgdatfile))]
				except:
					files = [file for file in loads(self.getUrl(f"{self.url}/file?dir=/").read())["files"] if basename(file).startswith("epg.dat")]
				epg_location = files[0] if files else None
			except Exception as e:
				print(f"[Import Channels] Exception: {str(e)}")
				self.ImportChannelsDone(False, _("Error while retrieving location of epg.dat on the fallback receiver"))
				return
			if epg_location:
				print("[Import Channels] Copy EPG file...")
				try:
					open(join(self.tmp_dir, "epg.dat"), "wb").write(self.getUrl(f"{self.url}/file?file={epg_location}").read())
				except Exception as e:
					print(f"[Import Channels] Exception: {str(e)}")
					self.ImportChannelsDone(False, _("Error while retrieving epg.dat from the fallback receiver"))
					return
				try:
					move(join(self.tmp_dir, "epg.dat"), config.misc.epgcache_filename.value)
				except:
					# follow same logic as in epgcache.cpp
					try:
						move(join(self.tmp_dir, "epg.dat"), "/epg.dat")
					except OSError as e:
						print(f"[Import Channels] Exception: {str(e)}")
						self.ImportChannelsDone(False, _("Error while moving epg.dat to its destination"))
						return
			else:
				self.ImportChannelsDone(False, _("No epg.dat file found on the fallback receiver"))

		if "channels" in self.remote_fallback_import:
			print("[Import Channels] Enumerate remote files")
			files = self.ImportGetFilelist(True, "bouquets.tv", "bouquets.radio")

			print("[Import Channels] Enumerate remote support files")
			supportfiles = ("lamedb", "blacklist", "whitelist", "alternatives.")

			for file in loads(self.getUrl(f"{self.url}/file?dir={self.e2path}").read())["files"]:
				if basename(file).startswith(supportfiles):
					files.append(file.replace(self.e2path, ""))

			print("[Import Channels] Fetch remote files")
			for file in files:
#				print("[Import Channels] Downloading %s..." % file)
				try:
					open(join(self.tmp_dir, basename(file)), "wb").write(self.getUrl(f"{self.url}/file?file={self.e2path}/{quote(file)}").read())
				except Exception as e:
					print(f"[Import Channels] Exception: {str(e)}")

			print("[Import Channels] Enumerate local files")
			files = self.ImportGetFilelist(False, "bouquets.tv", "bouquets.radio")

			print("[Import Channels] Removing old local files...")
			for file in files:
#				print("- Removing %s..." % file)
				try:
					remove(join(self.e2path, file))
				except OSError:
					print(f"[Import Channels] File {file} did not exist")

			print("[Import Channels] Updating files...")
			files = [x for x in listdir(self.tmp_dir)]
			for file in files:
#				print("- Moving %s..." % file)
				move(join(self.tmp_dir, file), join(self.e2path, file))

		self.ImportChannelsDone(True, {"channels": _("Channels"), "epg": _("EPG"), "channels_epg": _("Channels and EPG")}[self.remote_fallback_import])

	def ImportChannelsDone(self, flag, message=None):
		rmtree(self.tmp_dir, True)
		if flag:
			AddNotificationWithID("ChannelsImportOK", MessageBox, _("%s imported from fallback tuner") % message, type=MessageBox.TYPE_INFO, timeout=5)
		else:
			AddNotificationWithID("ChannelsImportNOK", MessageBox, _("Import from fallback tuner failed, %s") % message, type=MessageBox.TYPE_ERROR, timeout=5)
