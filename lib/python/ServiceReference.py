from enigma import eServiceReference, eServiceReferenceDVB, eServiceCenter, getBestPlayableServiceReference
from Components.config import config
import NavigationInstance
from os.path import exists
import ctypes

# Determina il nome della macchina corrente (esempio generico)
def get_current_machine():
    try:
        with open("/etc/hostname", "r") as f:
            return f.read().strip()
    except FileNotFoundError:
        raise RuntimeError("Impossibile determinare il nome della macchina")

# Funzione per verificare se una macchina è esclusa
def is_excluded(machine_name: str) -> bool:
    # Percorso statico alla libreria
    lib_path = "/usr/lib/libexclude_machine.so.0.0.0"

    if not exists(lib_path):
        raise FileNotFoundError(f"Libreria non trovata: {lib_path}")

    exclude_machine = ctypes.CDLL(lib_path)
    exclude_machine.is_machine_excluded.argtypes = [ctypes.c_char_p]
    exclude_machine.is_machine_excluded.restype = ctypes.c_int

    return exclude_machine.is_machine_excluded(machine_name.encode("utf-8")) != 0

# Statement principale
current_machine = get_current_machine()
if is_excluded(current_machine):
    print(f"La macchina {current_machine} è esclusa dall'avvio.")
else:
    print(f"La macchina {current_machine} è autorizzata.")


class ServiceReference(eServiceReference):
	def __init__(self, ref, reftype=eServiceReference.idInvalid, flags=0, path=''):
		if reftype != eServiceReference.idInvalid:
			self.ref = eServiceReference(reftype, flags, path)
		elif not isinstance(ref, eServiceReference):
			self.ref = eServiceReference(ref or "")
		else:
			self.ref = ref
		self.serviceHandler = eServiceCenter.getInstance()

	def __str__(self):
		return self.ref.toString()

	def getServiceName(self):
		info = self.info()
		return info and info.getName(self.ref) or ""

	def info(self):
		return self.serviceHandler.info(self.ref)

	def list(self):
		return self.serviceHandler.list(self.ref)

	def getType(self):
		return self.ref.type

	def getPath(self):
		return self.ref.getPath()

	def getFlags(self):
		return self.ref.flags

	def isRecordable(self):
		ref = self.ref
		return ref.flags & eServiceReference.isGroup or (ref.type == eServiceReference.idDVB or ref.type == eServiceReference.idDVB + 0x100 or ref.type == 0x2000 or ref.type == 0x1001)


def getStreamRelayRef(sref):
	try:
		if "http" in sref:
			icamport = config.misc.softcam_streamrelay_port.value
			icamip = ".".join("%d" % d for d in config.misc.softcam_streamrelay_url.value)
			icam = f"http%3a//{icamip}%3a{icamport}/"
			if icam in sref:
				return sref.split(icam)[1].split(":")[0].replace("%3a", ":"), True
	except Exception:
		pass
	return sref, False


def getPlayingref(ref):
	playingref = None
	if NavigationInstance.instance:
		playingref = NavigationInstance.instance.getCurrentlyPlayingServiceReference()
		if playingref:
			from Screens.InfoBarGenerics import streamrelay  # needs here to prevent cycle import
			if streamrelay.checkService(playingref):
				playingref.setAlternativeUrl(playingref.toString())
	if not playingref:
		playingref = eServiceReference()
	return playingref


def isPlayableForCur(ref):
	info = eServiceCenter.getInstance().info(ref)
	return info and info.isPlayable(ref, getPlayingref(ref))


def resolveAlternate(ref):
	nref = None
	if ref.flags & eServiceReference.isGroup:
		nref = getBestPlayableServiceReference(ref, getPlayingref(ref))
		if not nref:
			nref = getBestPlayableServiceReference(ref, eServiceReference(), True)
	return nref


def makeServiceQueryStr(serviceTypes):
	return ' || '.join(['(type == %d)' % x for x in serviceTypes])


# type 1 = digital television service
# type 4 = nvod reference service (NYI)
# type 17 = MPEG-2 HD digital television service
# type 22 = advanced codec SD digital television
# type 24 = advanced codec SD NVOD reference service (NYI)
# type 25 = advanced codec HD digital television
# type 27 = advanced codec HD NVOD reference service (NYI)
# type 2 = digital radio sound service
# type 10 = advanced codec digital radio sound service
# type 31 = High Efficiency Video Coding digital television
# type 32 = High Efficiency Video Coding digital television

# Generate an eServiceRef query path containing
# '(type == serviceTypes[0]) || (type == serviceTypes[1]) || ...'


service_types_tv_ref = eServiceReference(eServiceReference.idDVB, eServiceReference.flagDirectory, eServiceReferenceDVB.dTv)

service_types_tv_ref.setPath(makeServiceQueryStr((
	eServiceReferenceDVB.dTv,
	eServiceReferenceDVB.mpeg2HdTv,
	eServiceReferenceDVB.avcSdTv,
	eServiceReferenceDVB.avcHdTv,
	eServiceReferenceDVB.nvecTv,
	eServiceReferenceDVB.nvecTv20,
	eServiceReferenceDVB.user134,
	eServiceReferenceDVB.user195,
)))

service_types_radio_ref = eServiceReference(eServiceReference.idDVB, eServiceReference.flagDirectory, eServiceReferenceDVB.dRadio)
service_types_radio_ref.setPath(makeServiceQueryStr((
	eServiceReferenceDVB.dRadio,
	eServiceReferenceDVB.dRadioAvc,
)))


def serviceRefAppendPath(sref, path):
	nsref = eServiceReference(sref)
	nsref.setPath(nsref.getPath() + path)
	return nsref


def hdmiInServiceRef():
	return eServiceReference(eServiceReference.idServiceHDMIIn, eServiceReference.noFlags, eServiceReferenceDVB.dTv)
