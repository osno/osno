from Components.ActionMap import ActionMap
import ctypes
from boxbranding import getMachineBuild
import os
machine = getMachineBuild()
lib_opd = ctypes.CDLL('/usr/lib/libOPD.so.0.0.0')
globalActionMap = ActionMap(["GlobalActions"])
globalActionMap.execBegin()
