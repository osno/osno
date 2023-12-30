from Components.ActionMap import HelpableActionMap
from Components.config import ConfigNothing, NoSave
from Components.Sources.StaticText import StaticText
from Screens.InfoBarGenerics import streamrelay
from Screens.Setup import Setup
from ServiceReference import ServiceReference

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



class StreamRelaySetup(Setup, CamSetupHelper):
        def __init__(self, session):
                self.serviceitems = []
                self.services = streamrelay.data.copy()
                Setup.__init__(self, session=session, setup="StreamRelay")
                self["key_yellow"] = StaticText()
                self["key_blue"] = StaticText()
                self["addActions"] = HelpableActionMap(self, ["ColorActions"], {
                        "yellow": (self.keyAddService, _("Play service with Stream Relay"))
                        }, prio=0, description=_("Stream Relay Setup Actions"))
                self["removeActions"] = HelpableActionMap(self, ["ColorActions"], {
                        "blue": (self.keyRemoveService, _("Play service without Stream Relay"))
                        }, prio=0, description=_("Stream Relay Setup Actions"))
                self["removeActions"].setEnabled(False)

        def layoutFinished(self):
                Setup.layoutFinished(self)
                self.createItems()

        def createItems(self):
                self.serviceitems = []
                for serviceref in self.services:
                        service = ServiceReference(serviceref)
                        orbPos, orbPosText = self.getOrbPos(serviceref)
                        self.serviceitems.append((f"{service and service.getServiceName() or serviceref} / {orbPosText}", NoSave(ConfigNothing()), serviceref, orbPos))
                if self.serviceitems:
                        self.serviceitems.sort(key=self.sortService)
                        self.serviceitems.insert(0, ("**************************",))
                self.createSetup()

        def createSetup(self):
                Setup.createSetup(self, appendItems=self.serviceitems)

        def selectionChanged(self):
                self.updateButtons()
                Setup.selectionChanged(self)

        def updateButtons(self):
                if self.services and isinstance(self.getCurrentItem(), ConfigNothing):
                        self["removeActions"].setEnabled(True)
                        self["key_blue"].setText(_("Remove"))
                else:
                        self["removeActions"].setEnabled(False)
                        self["key_blue"].setText("")
                self["key_yellow"].setText(_("Add service"))

        def keySelect(self):
                if not isinstance(self.getCurrentItem(), ConfigNothing):
                        Setup.keySelect(self)

        def keyMenu(self):
                if not isinstance(self.getCurrentItem(), ConfigNothing):
                        Setup.keyMenu(self)

        def keyRemoveService(self):
                currentItem = self.getCurrentItem()
                if currentItem:
                        serviceref = self["config"].getCurrent()[2]
                        self.services.remove(serviceref)
                        index = self["config"].getCurrentIndex()
                        self.createItems()
                        self["config"].setCurrentIndex(index)

        def keyAddService(self):
                def keyAddServiceCallback(*result):
                        if result:
                                service = ServiceReference(result[0])
                                serviceref = service.ref.toCompareString()
                                if serviceref not in self.services:
                                        self.services.append(serviceref)
                                        self.createItems()
                                        self["config"].setCurrentIndex(2)

                from Screens.ChannelSelection import SimpleChannelSelection  # This must be here to avoid a boot loop!
                self.session.openWithCallback(keyAddServiceCallback, SimpleChannelSelection, _("Select"), currentBouquet=False)

        def keySave(self):
                if streamrelay.data != self.services:
                        streamrelay.data = self.services
                streamrelay.data = self.services
                Setup.keySave(self)
