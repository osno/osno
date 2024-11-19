from os import listdir, system
from os.path import abspath, dirname, exists, ismount, join
from subprocess import Popen, PIPE
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

opkgDestinations = ['/']
opkgStatusPath = ''
overwriteSettingsFiles = False
overwriteDriversFiles = True
overwriteEmusFiles = True
overwritePiconsFiles = True
overwriteBootlogoFiles = True
overwriteSpinnerFiles = True


def findMountPoint(path):
	"""Example: findMountPoint("/media/hdd/some/file") returns "/media/hdd\""""
	path = abspath(path)
	while not ismount(path):
		path = dirname(path)
	return path


def opkgExtraDestinations():
	global opkgDestinations
	return ''.join([f" --add-dest {i}:{i}" for i in opkgDestinations])


def opkgAddDestination(mountpoint):
	global opkgDestinations
	if mountpoint not in opkgDestinations:
		opkgDestinations.append(mountpoint)
		print("[OPKG] Added to OPKG destinations:", mountpoint)


mounts = listdir('/media')
for mount in mounts:
	mount = join('/media', mount)
	if mount and not mount.startswith('/media/net'):
		if opkgStatusPath == '':
			# recent opkg versions
			opkgStatusPath = 'var/lib/opkg/status'
			if not exists(join('/', opkgStatusPath)):
				# older opkg versions
				opkgStatusPath = 'usr/lib/opkg/status'
		if exists(join(mount, opkgStatusPath)):
			opkgAddDestination(mount)


def getValue(line):
	dummy = line.split('=')
	if len(dummy) != 2:
		print("Error: Wrong formatted settings file")
		exit
	if dummy[1] == "false":
		return False
	elif dummy[1] == "true":
		return True
	else:
		return False


# get list of upgradable packages
p = Popen("opkg list-upgradable", stdout=PIPE, stderr=PIPE, shell=True, text=True)
stdout, stderr = p.communicate()

if stderr != "":
	print("Error occurred:", stderr)
	exit

# read configuration
try:
	f = open("/etc/enigma2/settings")
	lines = f.readlines()
	f.close()
except:
	print("Error opening /etc/enigma2/settings file")

for line in lines:
	if line.startswith("config.plugins.softwaremanager.overwriteSettingsFiles"):
		overwriteSettingsFiles = getValue(line)
	elif line.startswith("config.plugins.softwaremanager.overwriteDriversFiles"):
		overwriteDriversFiles = getValue(line)
	elif line.startswith("config.plugins.softwaremanager.overwriteEmusFiles"):
		overwriteEmusFiles = getValue(line)
	elif line.startswith("config.plugins.softwaremanager.overwritePiconsFiles"):
		overwritePiconsFiles = getValue(line)
	elif line.startswith("config.plugins.softwaremanager.overwriteBootlogoFiles"):
		overwriteBootlogoFiles = getValue(line)
	elif line.startswith("config.plugins.softwaremanager.overwriteSpinnerFiles"):
		overwriteSpinnerFiles = getValue(line)

# Split lines
packages = stdout.split('\n')
try:
	packages.remove("")
except:
	pass

# Check for packages which should not be upgraded and remove them from list
upgradePackages = []
for package in packages:
	item = package.split(' - ', 2)
	if item[0].find('-settings-') > -1 and not overwriteSettingsFiles:
		continue
	elif item[0].find('kernel-module-') > -1 and not overwriteDriversFiles:
		continue
	elif item[0].find('-softcams-') > -1 and not overwriteEmusFiles:
		continue
	elif item[0].find('-picons-') > -1 and not overwritePiconsFiles:
		continue
	elif item[0].find('-bootlogo') > -1 and not overwriteBootlogoFiles:
		continue
	elif item[0].find('opendroid-spinner') > -1 and not overwriteSpinnerFiles:
		continue
	else:
		upgradePackages.append(item[0])

for p in upgradePackages:
	system('opkg ' + opkgExtraDestinations() + ' upgrade ' + p + ' 2>&1 | tee /home/root/ipkgupgrade.log')

# Reboot box
system('reboot')
