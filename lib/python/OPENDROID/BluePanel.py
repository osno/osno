from enigma import eTimer
from os import listdir, readlink
from os.path import exists, isfile, islink, join, split as pathsplit
from socket import socket, AF_UNIX, SOCK_STREAM
from twisted.internet.reactor import callInThread
from enigma import iServiceInformation, getDesktop
from ServiceReference import ServiceReference
from Components.ActionMap import HelpableActionMap
from Components.config import ConfigNothing, ConfigSelection, NoSave, config
from Components.ScrollLabel import ScrollLabel
from Components.Label import Label
from Components.Sources.StaticText import StaticText
from Components.SystemInfo import updateSysSoftCam, BoxInfo
from Screens.InfoBarGenerics import autocam, streamrelay
from Screens.Processing import Processing
from Screens.Screen import Screen
from Screens.Setup import Setup
from Tools.Directories import isPluginInstalled
from Tools.GetEcmInfo import GetEcmInfo


class CamControl:
        '''CAM convention is that a softlink named /etc/init.c/softcam.* points
        to the start/stop script.'''

        def __init__(self, name):
                self.callbackTimer = eTimer()
                self.name = name
                self.notFound = None
                self.link = join("/etc/init.d", name)
                if not exists(self.link):
                        print(f"[CamControl] No softcam link: '{self.link}'")
                        if islink(self.link) and exists("/etc/init.d/softcam.None"):
                                target = self.current()
                                if target:
                                        self.notFound = target
                                        print(f"[CamControl] wrong target '{target}' set to None")
                                        self.switch("None", None)  # wrong link target set to None

        def getList(self):
                result = []
                prefix = f"{self.name}."
                for f in listdir("/etc/init.d"):
                        if f.startswith(prefix):
                                result.append(f[len(prefix):])
                return result

        def current(self):
                try:
                        l = readlink(self.link)
                        prefix = f"{self.name}."
                        if prefix in l:
                                return pathsplit(l)[1].split(prefix, 2)[1]
                except (OSError, IndexError):
                        pass
                return None

        def switch(self, newcam, callback):
                self.callback = callback
                self.deamonSocket = socket(AF_UNIX, SOCK_STREAM)
                self.deamonSocket.connect("/tmp/deamon.socket")
                self.deamonSocket.send(f"SWITCH_{self.name.upper()},{newcam}".encode())
                self.waitSocket()

        def restart(self, callback):
                self.callback = callback
                self.deamonSocket = socket(AF_UNIX, SOCK_STREAM)
                self.deamonSocket.connect("/tmp/deamon.socket")
                self.deamonSocket.send(f"RESTART,{self.name}".encode())
                self.waitSocket()

        def waitSocket(self):
                self.callbackTimer.timeout.get().append(self.closeSocket)
                self.callbackTimer.start(5000, False)
                callInThread(self.listenSocket)

        def listenSocket(self):
                data = None
                while not data:
                        data = self.deamonSocket.recv(256)
                self.closeSocket()

        def closeSocket(self):
                self.callbackTimer.stop()
                if self.deamonSocket:
                        self.deamonSocket.close()
                if self.callback:
                        self.callback()


class CamSetupCommon(Setup):
        def __init__(self, session, setup):
                self.switchTimer = eTimer()
                self.oldServiceRef = None
                Setup.__init__(self, session=session, setup=setup)
                self["key_yellow"] = StaticText()
                self["restartActions"] = HelpableActionMap(self, ["ColorActions"], {
                        "yellow": (self.keyRestart, _("Immediately restart selected devices."))
                        }, prio=0, description=_("Softcam Actions"))
                self["restartActions"].setEnabled(False)

        def updateRestartButton(self, canrestart):
                self["key_yellow"].setText(_("Restart") if canrestart else "")
                self["restartActions"].setEnabled(canrestart)

        def keyRestart(self):  # This function needs to overwrite
                pass

        def updateButtons(self):  # This function needs to overwrite
                pass

        def selectionChanged(self):
                self.updateButtons()
                Setup.selectionChanged(self)

        def changedEntry(self):
                self.updateButtons()
                Setup.changedEntry(self)

        def showProcess(self, stopService):
                if stopService:
                        self.oldServiceRef = self.session.nav.getCurrentlyPlayingServiceOrGroup()
                        self.session.nav.stopService()
                Processing.instance.setDescription(_("Restarting..."))
#                Processing.instance.showProgress(endless=True)


class CardserverSetup(CamSetupCommon):
        def __init__(self, session):
                self.servicetype = "cardserver"
                self.camctrl = CamControl(self.servicetype)
                cardservers = self.camctrl.getList()
                defaultcardserver = self.camctrl.current()
                if not cardservers:
                        cardservers = [("", _("None"))]
                        defaultcardserver = ""
                config.misc.cardservers = ConfigSelection(default=defaultcardserver, choices=cardservers)
                CamSetupCommon.__init__(self, session=session, setup="Cardserver")

        def updateButtons(self):
                self.updateRestartButton(config.misc.cardservers.value and config.misc.cardservers.value.lower() != "none")

        def keySave(self):
                if config.misc.cardservers.value != self.camctrl.current():
                        self.showProcess(False)
                        self.camctrl.switch(config.misc.cardservers.value, self.saveDone)

        def keyRestart(self):
                self.showProcess(False)
                self.camctrl.restart(self.restartDone)

        def restartDone(self):
                if self.oldServiceRef:
                        self.session.nav.playService(self.oldServiceRef, adjust=False)
                self.saveAll()
                updateSysSoftCam()
#                Processing.instance.hideProgress()

        def saveDone(self):
                self.restartDone()
                self.close()


class BluePanel(CamSetupCommon):
        skin = """
	<screen name="BluePanel" position="center,center" size="560,450" >
		<widget name="config" position="5,10" size="550,90" />
		<widget name="info" position="5,100" size="550,300" font="Fixed;18" />
		<ePixmap name="red" position="0,410" zPosition="1" size="140,40" pixmap="skin_default/buttons/red.png" transparent="1" alphatest="on" />
		<ePixmap name="green" position="140,410" zPosition="1" size="140,40" pixmap="skin_default/buttons/green.png" transparent="1" alphatest="on" />
		<widget objectTypes="key_red,StaticText" source="key_red" render="Label" position="0,410" zPosition="2" size="140,40" valign="center" halign="center" font="Regular;21" transparent="1" shadowColor="black" shadowOffset="-1,-1" />
		<widget objectTypes="key_green,StaticText" source="key_green" render="Label" position="140,410" zPosition="2" size="140,40" valign="center" halign="center" font="Regular;21" transparent="1" shadowColor="black" shadowOffset="-1,-1" />
		<widget objectTypes="key_blue,StaticText" source="key_blue" render="Label"  position="420,410" zPosition="2" size="140,40" valign="center" halign="center" font="Regular;21" transparent="1" shadowColor="black" shadowOffset="-1,-1"/>
		<widget objectTypes="key_blue,StaticText" source="key_blue" render="Pixmap" pixmap="skin_default/buttons/blue.png"  position="420,410" zPosition="1" size="140,40" transparent="1" alphatest="on">
			<convert type="ConditionalShowHide"/>
		</widget>
	</screen>"""

        def __init__(self, session):
                Screen.__init__(self, session)
                self.servicetype = "softcam"
                self.camctrl = CamControl(self.servicetype)
                self.ecminfo = GetEcmInfo()
                softcams = self.camctrl.getList()
                defaultsoftcam = self.camctrl.current()
                if not softcams:
                        softcams = [("", _("None"))]
                        defaultsoftcam = ""
                config.misc.softcams = ConfigSelection(default=defaultsoftcam, choices=softcams)
                if self.camctrl.notFound:
                        print("[SoftcamSetup] current: '%s' not found" % self.camctrl.notFound)
                        config.misc.softcams.value = "None"
                        config.misc.softcams.save()
                CamSetupCommon.__init__(self, session=session, setup="Softcam")
                self["key_blue"] = StaticText()
                self["infoActions"] = HelpableActionMap(self, ["ColorActions"], {
                        "blue": (self.softcamInfo, _("Display oscam information."))
                        }, prio=0, description=_("Softcam Actions"))
                self["infoActions"].setEnabled(False)
                (newEcmFound, ecmInfo) = self.ecminfo.getEcm()
                self["info"] = ScrollLabel("".join(ecmInfo))
                self.EcmInfoPollTimer = eTimer()
                self.EcmInfoPollTimer.callback.append(self.setEcmInfo)
                self.EcmInfoPollTimer.start(1000)
                self.onShown.append(self.updateButtons)
                try:
                        service = self.session.nav.getCurrentService()
                        info = service and service.info()
                        videosize = str(info.getInfo(iServiceInformation.sVideoWidth)) + 'x' + str(info.getInfo(iServiceInformation.sVideoHeight))
                        aspect = info.getInfo(iServiceInformation.sAspect)
                        if aspect in (1, 2, 5, 6, 9, 10, 13, 14):
                                aspect = '4:3'
                        else:
                                aspect = '16:9'
                                provider = info.getInfoString(iServiceInformation.sProvider)
                                chname = ServiceReference(self.session.nav.getCurrentlyPlayingServiceReference()).getServiceName()
                                self['lb_provider'] = Label(_('Provider: ') + provider)
                                self['lb_channel'] = Label(_('Name: ') + chname)
                                self['lb_aspectratio'] = Label(_('Aspect Ratio: ') + aspect)
                                self['lb_videosize'] = Label(_('Video Size: ') + videosize)
                except:
                        self['lb_provider'] = Label(_('Provider: n/a'))
                        self['lb_channel'] = Label(_('Name: n/a'))
                        self['lb_aspectratio'] = Label(_('Aspect Ratio: n/a'))
                        self['lb_videosize'] = Label(_('Video Size: n/a'))

        def keySave(self):
                if config.misc.softcams.value != self.camctrl.current():
                        self.showProcess(True)
                        self.camctrl.switch(config.misc.softcams.value, self.saveDone)
                else:
                        self.saveDone()

        def keyRestart(self):
                self.showProcess(True)
                self.camctrl.restart(self.restartDone)

        def saveDone(self):
                self.restartDone()
                self.close()

        def restartDone(self):
                if self.oldServiceRef:
                        self.session.nav.playService(self.oldServiceRef, adjust=False)
                self.saveAll()
                updateSysSoftCam()
#                Processing.instance.hideProgress()

        def updateButtons(self):
                valid = config.misc.softcams.value and config.misc.softcams.value.lower() != "none"
                self["key_blue"].setText(_("Info") if valid else "")
                self["infoActions"].setEnabled(valid)
                self.updateRestartButton(valid)

        def softcamInfo(self):
                ppanelFilename = "/etc/ppanels/%s.xml" % config.misc.softcams.value
                if "oscam" in config.misc.softcams.value.lower():  # and isfile('/usr/lib/enigma2/python/Screens/OScamInfo.py'):
                        from Screens.OScamInfo import OSCamInfo
                        self.session.open(OSCamInfo)
                elif "cccam" in config.misc.softcams.value.lower():  # and isfile('/usr/lib/enigma2/python/Screens/CCcamInfo.py'):
                        from Screens.CCcamInfo import CCcamInfoMain
                        self.session.open(CCcamInfoMain)
                elif isfile(ppanelFilename) and isPluginInstalled("PPanel"):
                        from Plugins.Extensions.PPanel.ppanel import PPanel
                        self.session.open(PPanel, name="%s PPanel" % config.misc.softcams.value, node=None, filename=ppanelFilename, deletenode=None)

        def setEcmInfo(self):
                (newEcmFound, ecmInfo) = self.ecminfo.getEcm()
                if newEcmFound:
                        self["info"].setText("".join(ecmInfo))


class CamSetupHelper:
        def getOrbPos(self, sref):
                orbpos = 0
                orbposText = ""
                try:
                        orbpos = int(sref.split(":")[6], 16) >> 16
                        if 1 <= orbpos <= 3600:
                                if orbpos > 1800:  # West.
                                        orbpos = 3600 - orbpos
                                        direction = _("W")
                                else:
                                        direction = _("E")
                                orbposText = "%d.%d %s%s" % (orbpos / 10, orbpos % 10, "\u00B0", direction)
                except:
                        pass
                return orbpos, orbposText

        def sortService(self, item):
                return (item[3], item[0].lower() if item and item[0] and ord(item[0].lower()[0]) in range(97, 123) else f"zzzzz{item[0].lower()}")


class AutocamSetup(Setup, CamSetupHelper):
        def __init__(self, session):
                self.softcams = BoxInfo.getItem("Softcams")
                defaultsoftcam = BoxInfo.getItem("CurrentSoftcam")
                self.camitems = []
                self.services = []
                self.autocamData = autocam.data.copy()
                defaultsoftcams = [x for x in self.softcams if x != "None"]
                self.defaultautocam = config.misc.autocamDefault.value or defaultsoftcam
                self.autocamDefault = ConfigSelection(default=self.defaultautocam, choices=defaultsoftcams)
                Setup.__init__(self, session=session, setup="AutoCam")
                self["key_yellow"] = StaticText()
                self["key_blue"] = StaticText()
                self["addActions"] = HelpableActionMap(self, ["ColorActions"], {
                        "yellow": (self.keyAddService, _("Add service to AutoCam"))
                        }, prio=0, description=_("AutoCam Setup Actions"))
                self["addActions"].setEnabled(config.misc.autocamEnabled.value)
                self["removeActions"] = HelpableActionMap(self, ["ColorActions"], {
                        "blue": (self.keyRemoveService, _("Remove service from AutoCam"))
                        }, prio=0, description=_("AutoCam Setup Actions"))
                self["removeActions"].setEnabled(False)

        def layoutFinished(self):
                Setup.layoutFinished(self)
                self.createItems()

        def createItems(self):
                self.camitems = []
                if config.misc.autocamEnabled.value:
                        for serviceref in self.autocamData.keys():
                                self.services.append(serviceref)
                                cam = self.autocamData[serviceref]
                                service = ServiceReference(serviceref)
                                orbPos, orbPosText = self.getOrbPos(serviceref)
                                self.camitems.append((f"{service and service.getServiceName() or serviceref} / {orbPosText}", ConfigSelection(default=cam, choices=self.softcams), serviceref, orbPos))
                        if self.camitems:
                                self.camitems.sort(key=self.sortService)
                                self.camitems.insert(0, ("**************************",))
                self.createSetup()

        def createSetup(self):
                Setup.createSetup(self, appendItems=self.camitems)

        def selectionChanged(self):
                self.updateButtons()
                Setup.selectionChanged(self)

        def changedEntry(self):
                Setup.changedEntry(self)
                self.updateButtons()
                current = self["config"].getCurrent()
                if current:
                        if current[1] == config.misc.autocamEnabled:
                                self.createItems()
                                return
                        elif current[1] == self.autocamDefault:
                                return
                        newcam = current[1].value
                        serviceref = current[2]
                        if self.autocamData[serviceref] != newcam:
                                self.autocamData[serviceref] = newcam

        def updateButtons(self):
                currentItem = self.getCurrentItem()
                if currentItem in (config.misc.autocamEnabled, self.autocamDefault):
                        self["removeActions"].setEnabled(False)
                        self["key_blue"].setText("")
                else:
                        self["removeActions"].setEnabled(True)
                        self["key_blue"].setText(_("Remove"))
                self["addActions"].setEnabled(config.misc.autocamEnabled.value)
                self["key_yellow"].setText(_("Add service") if config.misc.autocamEnabled.value else "")

        def keyRemoveService(self):
                currentItem = self.getCurrentItem()
                if currentItem in (config.misc.autocamEnabled, self.autocamDefault):
                        return
                elif currentItem:
                        serviceref = self["config"].getCurrent()[2]
                        del self.autocamData[serviceref]
                        index = self["config"].getCurrentIndex()
                        self.createItems()
                        self["config"].setCurrentIndex(index)

        def keyAddService(self):
                def keyAddServiceCallback(*result):
                        if result:
                                service = ServiceReference(result[0])
                                serviceref = service.ref.toCompareString()
                                if serviceref not in self.autocamData:
                                        newData = {serviceref: self.defaultautocam}
                                        newData.update(self.autocamData)
                                        self.autocamData = newData
                                        self.createItems()
                                        self["config"].setCurrentIndex(2)

                from Screens.ChannelSelection import SimpleChannelSelection  # This must be here to avoid a boot loop!
                self.session.openWithCallback(keyAddServiceCallback, SimpleChannelSelection, _("Select"), currentBouquet=True)

        def keySave(self):
                if config.misc.autocamEnabled.value:
                        if autocam.data != self.autocamData:
                                autocam.data = self.autocamData
                        config.misc.autocamDefault.value = self.autocamDefault.value
                        config.misc.autocamDefault.save()
                config.misc.autocamEnabled.save()
                self.close()


