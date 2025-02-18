# -*- coding: utf-8 -*-
#from . import _
from Plugins.Plugin import PluginDescriptor
from Screens.Screen import Screen
from Screens.MessageBox import MessageBox
from Screens.ChoiceBox import ChoiceBox
from Screens.Console import Console
from Components.ActionMap import ActionMap, NumberActionMap
from Components.MultiContent import MultiContentEntryText, MultiContentEntryPixmapAlphaTest, MultiContentEntryPixmap, MultiContentEntryPixmapAlphaBlend
from Components.Sources.List import List
from Components.Sources.StaticText import StaticText
from Components.config import config, configfile, getConfigListEntry, ConfigSelection, ConfigSubsection, ConfigDirectory, ConfigText, ConfigPassword, ConfigIP, ConfigInteger, ConfigYesNo
from Components.ConfigList import ConfigList, ConfigListScreen
from Components.MenuList import MenuList
from Components.Label import Label
from Components.ScrollLabel import ScrollLabel
from Components.Button import Button
try:
	from OpenSSL import SSL
except ImportError:
	pass
from Tools.LoadPixmap import LoadPixmap
from Tools.Directories import fileExists, resolveFilename, SCOPE_CURRENT_PLUGIN
from enigma import eTimer, quitMainloop, RT_HALIGN_LEFT, RT_HALIGN_CENTER, RT_VALIGN_CENTER, eListboxPythonMultiContent, eListbox, gFont, getDesktop, ePicLoad, eSize, ePoint
from xml.etree import ElementTree
from xml.parsers.expat import ExpatError
import socket
from operator import itemgetter
import os, re, time
import urllib, urllib2
from os import system
config.plugins.caminfo = ConfigSubsection()
config.plugins.caminfo.userdatafromconf = ConfigYesNo(default = False)
#config.plugins.caminfo.usehostname = ConfigYesNo(default = False)
config.plugins.caminfo.autoupdate = ConfigYesNo(default = False)
config.plugins.caminfo.username = ConfigText(default = "username", fixed_size = False, visible_width=12)
config.plugins.caminfo.password = ConfigPassword(default = "password", fixed_size = False)
config.plugins.caminfo.ip = ConfigIP( default = [ 127,0,0,1 ], auto_jump=True)
config.plugins.caminfo.serverip = ConfigIP( default = [ 127,0,0,1 ], auto_jump=True)
config.plugins.caminfo.hostname = ConfigText(default = "", fixed_size = False)
config.plugins.caminfo.port = ConfigInteger(default = 16002, limits=(0,65536) )
config.plugins.caminfo.intervall = ConfigInteger(default = 10, limits=(1,600) )
config.plugins.caminfo.restartServerCam = ConfigYesNo(default = False)
config.plugins.caminfo.CamBinaryPath = ConfigSelection(default="/usr/bin", choices=[
		("/usr/bin", _("/usr/bin")),
		("/usr/bin/cam", _("/usr/bin/cam")),
                ("/var/bin", _("/var/bin")),
		("/var/swap/bin", _("/var/swap/bin")),
		("/var/emu", _("/var/emu"))])
config.plugins.caminfo.CamConfigPath = ConfigSelection(default="/usr/keys", choices=[
		("/usr/keys", _("/usr/keys")),
		("/var/keys", _("/var/keys")),
		("/var/swap/keys", _("/var/swap/keys")),
		("/etc/tuxbox/config/OSCam-csat", _("/etc/tuxbox/config/OSCam-csat")),		
                ("/var/emu/keys", _("/var/emu/keys")),
		("/etc", _("/etc")),
		("/etc/tuxbox/config", _("/etc/tuxbox/config"))])
config.plugins.caminfo.ActivateCam = ConfigYesNo(default = False)
config.plugins.caminfo.CamSelect = ConfigSelection(default="oscam", choices=[
		("oscam", _("oscam")),
		("CCcam-2.2.1", _("CCcam-2.2.1")),	
	        ("GCam_1.3-r0", _("GCam_1.3-r0")),	       
	        ("Scam", _("Scam")),
        	("camd3", _("Camd3")),
		("gbox", _("Gbox")),
		("incubusCamd", _("incubusCamd")),
		("mbox", _("mbox")),
		("MgCamd_1.45", _("MgCamd_1.45"))])
config.plugins.caminfo.CamAutostart = ConfigYesNo(default = False)
CamSelect_old = config.plugins.caminfo.CamSelect.value

caminfo_version = "v0.8"

my_global_session = None
global_session = None

fb = getDesktop(0).size()
if fb.width() > 1024:
	sizeH = fb.width() - 100
	HDSKIN = True
else:
	# sizeH = fb.width() - 50
	sizeH = 700
	HDSKIN = False

class CamInfo:
	TYPE = 0
	NAME = 1
	PROT = 2
	CAID_SRVID = 3
	SRVNAME = 4
	ECMTIME = 5
	IP_PORT = 6
	ECMTIME = 7
	HEAD = { NAME: _("Label"), PROT: _("Protocol"),
		CAID_SRVID: "CAID:SrvID", SRVNAME: _("Serv.Name"),
		ECMTIME: _("ECM-Time"), IP_PORT: _("IP-Address") }
	version = ""

	def confPath(self):
#		search_dirs = [ "/usr", "/var", "/etc" ]
#		sdirs = " ".join(search_dirs)
#		cmd = 'find %s -name "oscam.conf"' % sdirs
		confdir = config.plugins.caminfo.CamConfigPath.value
		cmd = 'find %s -name "oscam.conf"' % confdir
		res = os.popen(cmd).read()
		if res == "":
			return None
		else:
			return res.replace("\n", "")


	def getUserData(self):
		err = ""
		self.oscamconf = self.confPath()
		self.username = ""
		self.password = ""
		if self.oscamconf is not None:
			data = open(self.oscamconf, "r").readlines()
			webif = False
			httpuser = httppwd = httpport = False
			for i in data:
				if "[webif]" in i.lower():
					webif = True
				elif "httpuser" in i.lower():
					httpuser = True
					user = i.split("=")[1].strip()
				elif "httppwd" in i.lower():
					httppwd = True
					pwd = i.split("=")[1].strip()
				elif "httpport" in i.lower():
					httpport = True
					port = i.split("=")[1].strip()
					self.port = port
					
			if not webif:
				err = _("There is no [webif] section in oscam.conf")
			elif not httpuser:
				err = _("No httpuser defined in oscam.conf")
			elif not httppwd:
				err = _("No httppwd defined in oscam.conf")
			elif not httpport:
				err = _("No httpport defined in oscam.conf. This value is required!")
			
			if err != "":
				return err
			else:
				return (user, pwd, port)
		else:
			return _("file oscam.conf could not be found")

	def openWebIF(self, part = None, reader = None, cmd = None):
		if config.plugins.caminfo.userdatafromconf.value:
			self.ip = "127.0.0.1"
			udata = self.getUserData()
			if isinstance(udata, str):
				if "httpuser" in udata:
					self.username=""
				elif "httppwd" in udata:
					self.password = ""
				else:
					return (False, udata)
			else:
				self.port = udata[2]
				self.username = udata[0]
				self.password = udata[1]
		else:
#			if config.plugins.caminfo.usehostname.value:
#				self.ip = socket.gethostbyname(config.plugins.caminfo.hostname.value)
#			else:
			self.ip = ".".join("%d" % d for d in config.plugins.caminfo.ip.value)
			self.port = config.plugins.caminfo.port.value
			self.username = config.plugins.caminfo.username.value
			self.password = config.plugins.caminfo.password.value
		if part is None:
			self.url = "http://%s:%s/oscamapi.html?part=status" % ( self.ip, self.port )
		else:
			self.url = "http://%s:%s/oscamapi.html?part=%s" % (self.ip, self.port, part )
		if part is not None and reader is not None:
			reader_enc = urllib.urlencode({"label":reader})
			self.url = "http://%s:%s/oscamapi.html?part=%s&%s" % ( self.ip, self.port, part, reader_enc )
		if cmd is not None and reader is not None:
			if cmd=="restart":
				reader_enc = urllib.urlencode({"label":reader})
				self.url = "http://%s:%s/status.html?action=restart&%s" % ( self.ip, self.port, reader_enc )
			
		print "URL=%s" % self.url
		pwman = urllib2.HTTPPasswordMgrWithDefaultRealm()
		pwman.add_password( None, self.url, self.username, self.password )
		handlers = urllib2.HTTPDigestAuthHandler( pwman )
		opener = urllib2.build_opener( urllib2.HTTPHandler, handlers )
		urllib2.install_opener( opener )
		request = urllib2.Request( self.url )
		err = False
		try:
			data = urllib2.urlopen( request ).read()
		except urllib2.URLError, e:
			if hasattr(e, "reason"):
				err = str(e.reason)
			elif hasattr(e, "code"):
				err = str(e.code)
		except IOError, e:
			ioerr = str(e)
			if ioerr.startswith("[Errno 131]"):
				err = _("IOError 131 (socket.error)\nMaybe you are using SSL which is not implemented yet in this plugin")
				
		if err is not False:
			print "[openWebIF] Fehler: %s" % err
			return (False, err)
		else:
			r = re.search("headline1\">OSCAM (.*)-(.*)#(\d{,4})<", data)
			if r is not None:
				vers = r.group(1)
				rev = r.group(3)
				if float(vers) < 1.0 or int(rev) < 4210:
					errmsg = "[CamInfo]: Error, wrong Cam Version ( V%s Build Rev. %s )\nAt least V1 Build Rev. 4210 is required for this plugin to work" % (vers, rev)
					print errmsg
					return (False, errmsg) 
			else:
				return (True, data)
			
	def readXML(self, typ):
		if typ == "l":
			self.showLog = True
			part = "status&appendlog=1"
		else:
			self.showLog = False
			part = None
		result = self.openWebIF(part)
		retval = []
		tmp = {}
		if result[0]:
			if not self.showLog:
				data = ElementTree.XML(result[1])
				status = data.find("status")
				clients = status.findall("client")
				for cl in clients:
					name = cl.attrib["name"]
					proto = cl.attrib["protocol"]
					if cl.attrib.has_key("au"):
						au = cl.attrib["au"]
					else:
						au = ""
					caid = cl.find("request").attrib["caid"]
					srvid = cl.find("request").attrib["srvid"]
					if cl.find("request").attrib.has_key("ecmtime"):
						ecmtime = cl.find("request").attrib["ecmtime"]
						if ecmtime == "":
							ecmtime = "n/a"
						else:
							ecmtime = str(float(ecmtime) / 1000)[:5]
					else:
						ecmtime = "not available"
					srvname = cl.find("request").text
					if srvname is not None:
						if ":" in srvname:
							srvname_short = srvname.split(":")[1].strip()
						else:
							srvname_short = srvname
					else:
						srvname_short = "n/A"
					login = cl.find("times").attrib["login"]
					online = cl.find("times").attrib["online"]
					if proto.lower() == "dvbapi":
						ip = ""
					else:
						ip = cl.find("connection").attrib["ip"]
						if ip == "0.0.0.0":
							ip = ""
					port = cl.find("connection").attrib["port"]
					connstatus = cl.find("connection").text
					if name != "" and name != "anonymous" and proto != "":
						try:
							tmp[cl.attrib["type"]].append( (name, proto, "%s:%s" % (caid, srvid), srvname_short, ecmtime, ip, connstatus) )
						except KeyError:
							tmp[cl.attrib["type"]] = []
							tmp[cl.attrib["type"]].append( (name, proto, "%s:%s" % (caid, srvid), srvname_short, ecmtime, ip, connstatus) )
			else:
				if "<![CDATA" not in result[1]:
					tmp = result[1].replace("<log>", "<log><![CDATA[").replace("</log>", "]]></log>")
				else:
					tmp = result[1]
				data = ElementTree.XML(tmp)
				log = data.find("log")
				logtext = log.text.strip()
			if typ == "s":
				if tmp.has_key("r"):
					for i in tmp["r"]:
						retval.append(i)
				if tmp.has_key("p"):
					for i in tmp["p"]:
						retval.append(i)
			elif typ == "c":
				if tmp.has_key("c"):
					for i in tmp["c"]:
						retval.append(i)
			elif typ == "l":
				tmp = logtext.split("\n")
				retval = []
				for i in tmp:
					tmp2 = i.split(" ")
					if len(tmp2) > 2:
						del tmp2[2]
						txt = ""
						for j in tmp2:
							txt += "%s " % j.strip()
						retval.append( txt )

			return retval

		else:
			return result[1]
	def getVersion(self):
		xmldata = self.openWebIF()
		if xmldata[0]:
			data = ElementTree.XML(xmldata[1])
			if data.attrib.has_key("version"):
				self.version = data.attrib["version"]
			else:
				self.version = "n/a"
			return self.version			
		else:
			self.version = "n/a"
		return self.version	

	def getTotalCards(self, reader):
		xmldata = self.openWebIF(part = "entitlement", reader = reader)
		if xmldata[0]:
			try:
				xmld = ElementTree.XML(xmldata[1])
				cards = xmld.find("reader").find("cardlist")
				cardTotal = cards.attrib["totalcards"]
				return cardTotal
			except ExpatError, err:
				errmsg = _("[osc.getTotalCards] Error in XML data\n%s") % ( err )
				print errmsg
				return errmsg
		else:
			return None
	def getReaders(self, spec = None):
		xmldata = self.openWebIF()
		readers = []
		if xmldata[0]:
			try:
				data = ElementTree.XML(xmldata[1])
				status = data.find("status")
				clients = status.findall("client")
				for cl in clients:
					if cl.attrib.has_key("type"):
						if cl.attrib["type"] == "p" or cl.attrib["type"] == "r":
							if spec is not None:
								proto = cl.attrib["protocol"]
								if spec in proto:
									name = cl.attrib["name"]
									cards = self.getTotalCards(name)
									if isinstance(cards, str) and cards.startswith("[osc."):
										raise ValueError(cards)
									readers.append( ( "%s ( %s Cards )" % (name, cards), name) )
							else:
								readers.append( (cl.attrib["name"], cl.attrib["name"]) )  # return tuple for later use in Choicebox
				return readers
			except ExpatError, err:
				errmsg = _("[osc.getReaders] Error in XML data\n%s") % ( err )
				print errmsg
				return errmsg
			except ValueError, msg:
				print msg
				return msg
		else:
			return None
			
	def getClients(self):
		xmldata = self.openWebIF()
		clientnames = []
		if xmldata[0]:
			data = ElementTree.XML(xmldata[1])
			status = data.find("status")
			clients = status.findall("client")
			for cl in clients:
				if cl.attrib.has_key("type"):
					if cl.attrib["type"] == "c":
						readers.append( (cl.attrib["name"], cl.attrib["name"]) )  # return tuple for later use in Choicebox
			return clientnames
		else:
			return None
			
	def getECMInfo(self, ecminfo):
		result = []
		if os.path.exists(ecminfo):
			data = open(ecminfo, "r").readlines()
			for i in data:
				if "caid" in i:
					result.append( ("CAID", i.split(":")[1].strip()) )
				elif "pid" in i:
					result.append( ("PID", i.split(":")[1].strip()) )
				elif "prov" in i:
					result.append( (_("Provider"), i.split(":")[1].strip()) )
				elif "reader" in i:
					result.append( ("Reader", i.split(":")[1].strip()) )
				elif "from" in i:
					result.append( (_("Address"), i.split(":")[1].strip()) )
				elif "protocol" in i:
					result.append( (_("Protocol"), i.split(":")[1].strip()) )
				elif "hops" in i:
					result.append( ("Hops", i.split(":")[1].strip()) )
				elif "ecm time" in i:
					result.append( (_("ECM Time"), i.split(":")[1].strip()) )
			return result
		else:
			return "%s not found" % self.ecminfo
			
class oscMenuList(MenuList):
	def __init__(self, list, itemH = 25):
		MenuList.__init__(self, list, False, eListboxPythonMultiContent)
		self.l.setItemHeight(itemH)
		self.l.setFont(0, gFont("Regular", 18))
		self.l.setFont(1, gFont("Regular", 16))
		self.clientFont = gFont("Regular", 14)
		self.l.setFont(2, self.clientFont)
		self.l.setFont(3, gFont("Regular", 12))
		
class OscamInfoMenu(Screen):  
	skin = """
		<screen position="center,center" size="400, 300" title="OscamInfoMenu" >
			<widget enableWrapAround="1" name="mainmenu" position="10,10" size="380,280" scrollbarMode="showOnDemand" />
		</screen>"""
	
	def __init__(self, session):
		Screen.__init__(self, session)
		self.session = session
		self.menu = [ _("Restart-local-Cam"), _("Restart-ProxyServer(OSCam)"), _("Local-Cam-Setup"), _("ProxyServer(OSCam)-Setup"), _("Show-OSCam-Infos")] 
		self.osc = CamInfo()
		self["mainmenu"] = oscMenuList([])
		self["actions"] = NumberActionMap(["OkCancelActions", "InputActions", "ColorActions"],
					{
						"ok": self.ok,
						"cancel": self.exit,
						"red": self.red,
						"green": self.green,
						"yellow": self.yellow,
						"blue": self.blue,
						"1": self.keyNumberGlobal,
						"2": self.keyNumberGlobal,
						"3": self.keyNumberGlobal,
						"4": self.keyNumberGlobal,
						"5": self.keyNumberGlobal,
						"6": self.keyNumberGlobal,
						"7": self.keyNumberGlobal,
						"8": self.keyNumberGlobal,
						"9": self.keyNumberGlobal,
						"0": self.keyNumberGlobal,
						"up": self.up,
						"down": self.down
						}, -1)	
		self.onLayoutFinish.append(self.showMenu)
	
	def ok(self):
		selected = self["mainmenu"].getSelectedIndex()
		self.goEntry(selected)
	def cancel(self):
		self.close()
	def exit(self):
		self.close()
	def keyNumberGlobal(self, num):
		if num == 0:
			numkey = 10
		else:
			numkey = num
		if numkey < len(self.menu) - 3:
			self["mainmenu"].moveToIndex(numkey + 3)
			self.goEntry(numkey + 3)

	def red(self):
		self["mainmenu"].moveToIndex(0)
		self.goEntry(0)
	def green(self):
		self["mainmenu"].moveToIndex(1)
		self.goEntry(1)
	def yellow(self):
		self["mainmenu"].moveToIndex(2)
		self.goEntry(2)
	def blue(self):
		self["mainmenu"].moveToIndex(3)
		self.goEntry(3)
	def up(self):
		pass
	def down(self):
		pass
	def goEntry(self, entry):
		CamSelect = config.plugins.caminfo.CamSelect.value
		if entry == 0:
			if config.plugins.caminfo.ActivateCam.value:
				self.CamRestart()
			else:
				self.session.openWithCallback(self.ErrMsgCallback, MessageBox, _("Please Activate/Select Local-Cam first\n> Local-Cam-Setup!"), MessageBox.TYPE_ERROR, timeout=3)
		elif entry == 1:
			if config.plugins.caminfo.restartServerCam.value:
				if fileExists("/usr/lib/enigma2/python/EGAMI/restart_oscam_server_by_ssh.sh"):	
					self.session.open(Console,_("Restart-ProxyServer(OSCam)"),["/usr/lib/enigma2/python/EGAMI/restart_oscam_server_by_ssh.sh"])
			else:
				self.session.openWithCallback(self.ErrMsgCallbackProxy, MessageBox, _("Please Activate ProxyServer(OSCam) support first\n> ProxyServer(OSCam)-Setup!"), MessageBox.TYPE_ERROR, timeout=3)
		elif entry == 2:
			self.session.open(OscamInfoConfigScreen)
		elif entry == 3:
			self.session.open(ProxyServerConfigScreen)
		elif entry == 4:
			self.session.open(ShowOSCamInfoScreen)

	def CamRestart(self):
		bindir = config.plugins.caminfo.CamBinaryPath.value
		confdir = config.plugins.caminfo.CamConfigPath.value
		CamSelect = config.plugins.caminfo.CamSelect.value
		if config.plugins.caminfo.ActivateCam.value:
			system("echo 'stopping Cam now...'; echo '';mycams='oscam CCcam2_2_1 Scam gbox camd3 incubusCamd mbox mgcamd';for i in $mycams;do if pidof $i > /dev/null;then kill `pidof $i`;fi;done;for i in $mycams;do if pidof $i > /dev/null;then kill -9 `pidof $i`;fi;done")
			if CamSelect == "oscam":
				cmd = "(echo '(re)starting OSCam now...'; echo '';%s/%s -b -c %s) &" % (bindir, CamSelect, confdir)
				system(cmd)
			elif CamSelect == "CCcam2_2_1":
				cmd = "(echo '(re)starting CCcam2_2_1 now...'; echo '';%s/%s -C %s/CCcam.cfg) &" % (bindir, CamSelect, confdir)
				system(cmd)
			elif CamSelect == "Scam":
				cmd = "(echo '(re)starting Scam now...'; echo '';%s/%s) &" % (bindir, CamSelect)
				system(cmd)
			elif CamSelect == "camd3":
				cmd = "(echo '(re)starting camd3 now...'; echo '';%s/%s %s/camd3.config) &" % (bindir, CamSelect, confdir)
				system(cmd)
			elif CamSelect == "gbox":
				cmd = "(echo '(re)starting gbox now...'; echo '';%s/%s) &" % (bindir, CamSelect)
				system(cmd)
			elif CamSelect == "incubusCamd":
				cmd = "(echo '(re)starting incubusCamd now...'; echo '';%s/%s) &" % (bindir, CamSelect)
				system(cmd)
			elif CamSelect == "mbox":
				cmd = "(echo '(re)starting mbox now...'; echo '';%s/%s) &" % (bindir, CamSelect)
				system(cmd)
			elif CamSelect == "mgcamd":
				cmd = "(echo '(re)starting mgcamd now...'; echo '';%s/%s) &" % (bindir, CamSelect)
				system(cmd)
			isRunning = system("pidof %s" % CamSelect)
			if (isRunning is not None):
				self.session.open(MessageBox, config.plugins.caminfo.CamSelect.value + (" (re)startet!"), MessageBox.TYPE_INFO, timeout=3)
			else:
				self.session.open(MessageBox, config.plugins.caminfo.CamSelect.value + (" ERROR !!!"), MessageBox.TYPE_ERROR, timeout=3)

	def chooseReaderCallback(self, retval):
		print retval
		if retval is not None:
			if self.callbackmode == "cccam":
				self.session.open(oscEntitlements, retval[1])
			elif self.callbackmode == "restart":
				d = self.osc.openWebIF(reader="%s" % retval[1], cmd = "restart")
			else:
				self.session.open(oscReaderStats, retval[1])
				
	def ErrMsgCallback(self, retval):
		print retval
		self.session.open(OscamInfoConfigScreen)

	def ErrMsgCallbackProxy(self, retval):
		print retval
		self.session.open(ProxyServerConfigScreen)
		
	def buildMenu(self, mlist):
		keys = ["red", "green", "yellow", "blue", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", ""]
		menuentries = []
		y = 0
		for x in mlist:
			res = [ x ]
			if x.startswith("--"):
				png = LoadPixmap("/usr/share/enigma2/skin_default/div-h.png")
				if png is not None:
					res.append((eListboxPythonMultiContent.TYPE_PIXMAP, 10,0,360, 2, png))
					res.append((eListboxPythonMultiContent.TYPE_TEXT, 45, 3, 800, 25, 0, RT_HALIGN_LEFT, x[2:]))
					png2 = LoadPixmap("/usr/share/enigma2/skin_default/buttons/key_" + keys[y] + ".png")
					if png2 is not None:
						res.append((eListboxPythonMultiContent.TYPE_PIXMAP_ALPHATEST, 5, 3, 35, 25, png2))
			else:
				res.append((eListboxPythonMultiContent.TYPE_TEXT, 45, 00, 800, 25, 0, RT_HALIGN_LEFT, x))
				png2 = LoadPixmap("/usr/share/enigma2/skin_default/buttons/key_" + keys[y] + ".png")
				if png2 is not None:
					res.append((eListboxPythonMultiContent.TYPE_PIXMAP_ALPHATEST, 5, 0, 35, 25, png2))
			menuentries.append(res)
			if y < len(keys) - 1:
				y += 1
		return menuentries
	def showMenu(self):
		entr = self.buildMenu(self.menu)
		self.setTitle(_("OScamInfo Menu %s" % ( caminfo_version )))
		self["mainmenu"].l.setList(entr)
		self["mainmenu"].moveToIndex(0)
		
	def showErrorMessage(self, errmsg):
		self.session.open(MessageBox, errmsg, MessageBox.TYPE_ERROR, timeout = 10)
		


class oscReadMe(Screen):
	global HDSKIN
	if HDSKIN:
		sw = 900
	else:
		sw = 720
	skin = """<screen name="oscReadMe" position="center,center" size="%s, 500" title="Readme" >
			<widget enableWrapAround="1" name="status" position="10,20" size="%s,480" scrollbarMode="showOnDemand"/>
		</screen>""" % ( sw, sw - 10 )
	def __init__(self, session):
		Screen.__init__(self, session)
		self["status"] = oscMenuList([ ])			
		self["actions"] = ActionMap(["OkCancelActions"],
					{
						"ok": self.exit,
						"cancel": self.exit,
					}, -1)
		self.onLayoutFinish.append(self.getReadme)
		
	def exit(self):
		self.close()
		
	def buildList(self, listentry):
		entries = []
		for x in listentry:
			res = [ x ]
			res.append((eListboxPythonMultiContent.TYPE_TEXT, 0,0 , 720, 20, 1, RT_HALIGN_LEFT, x))
			entries.append(res)
		return entries
		
	def getReadme(self):
		readme_file = resolveFilename(SCOPE_CURRENT_PLUGIN, "Extensions/CamInfo/readme.txt")
		if os.path.exists(readme_file):
			readme = open(readme_file, "r").readlines()
		else:
			readme = [ _("readme.txt could not be found") ]
		msg = self.buildList(readme)
		self["status"].l.setItemHeight(30)
		self["status"].l.setList(msg)
		#self["status"].selectionEnabled(True)
	
	
		
class oscECMInfo(Screen, CamInfo):
	skin = """<screen position="center,center" size="500, 300" title="OScamInfo ECMInfo" >
			<widget enableWrapAround="1" name="output" position="10,10" size="580,300" scrollbarMode="showOnDemand" />
		</screen>"""
	def __init__(self, session):
		Screen.__init__(self, session)
		self.ecminfo = "/tmp/ecm.info"
		self["output"] = oscMenuList([])
		if config.plugins.caminfo.autoupdate.value:
			self.loop = eTimer()
			self.loop.callback.append(self.showData)
			timeout = config.plugins.caminfo.intervall.value * 1000
			self.loop.start(timeout, False)
		self["actions"] = ActionMap(["OkCancelActions"],
					{
						"ok": self.exit,
						"cancel": self.exit
					}, -1)
		self.onLayoutFinish.append(self.showData)
		
	def exit(self):
		if config.plugins.caminfo.autoupdate.value:
			self.loop.stop()
		self.close()
	def buildListEntry(self, listentry):
		return [
			None,
			(eListboxPythonMultiContent.TYPE_TEXT, 10, 10, 300, 30, 0, RT_HALIGN_LEFT, listentry[0]),
			(eListboxPythonMultiContent.TYPE_TEXT, 300, 10, 300, 30, 0, RT_HALIGN_LEFT, listentry[1])
			]
		
	def showData(self):
		data = self.getECMInfo(self.ecminfo)
		#print data
		out = []
		y = 0
		for i in data:
			out.append(self.buildListEntry(i))
		self["output"].l.setItemHeight(35)
		self["output"].l.setList(out)
		self["output"].selectionEnabled(True)
		
class oscInfo(Screen, CamInfo):
	def __init__(self, session, what):
		global HDSKIN, sizeH
		self.session = session
		self.what = what
		self.firstrun = True
		self.webif_data = self.readXML(typ = self.what)
		entry_count = len( self.webif_data )
		ysize = (entry_count + 4) * 25
		ypos = 10
		self.sizeLH = sizeH - 20	
		self.skin = """<screen position="center,center" size="%d, %d" title="Client Info" >""" % (sizeH, ysize)
		button_width = int(sizeH / 4)
		for k, v in enumerate(["red", "green", "yellow", "blue"]):
			xpos = k * button_width
			self.skin += """<ePixmap name="%s" position="%d,%d" size="35,25" pixmap="/usr/share/enigma2/skin_default/buttons/key_%s.png" zPosition="1" transparent="1" alphatest="on" />""" % (v, xpos, ypos, v)
			self.skin += """<widget source="key_%s" render="Label" position="%d,%d" size="%d,%d" font="Regular;16" zPosition="1" valign="center" transparent="1" />""" % (v, xpos + 40, ypos, button_width, 20)
		self.skin +="""<ePixmap name="divh" position="0,37" size="%d,2" pixmap="/usr/share/enigma2/skin_default/div-h.png" transparent="1" alphatest="on" />""" % sizeH
		self.skin +="""<widget name="output" position="10,45" size="%d,%d" zPosition="1" scrollbarMode="showOnDemand" />""" % ( self.sizeLH, ysize)
		self.skin +="""<widget name="status" position="10,45" size="%d,%d" zPosition="2" font="Regular; 18" />""" % ( self.sizeLH, ysize )
		self.skin += """</screen>""" 
		Screen.__init__(self, session)
		self.mlist = oscMenuList([])
		self["output"] = self.mlist
		self["status"] = Label("")
		self["status"].hide()
		self.errmsg = ""
		self["key_red"] = StaticText(_("Close"))
		if self.what == "c":
			self["key_green"] = StaticText("")
			self["key_yellow"] = StaticText("Servers")
			self["key_blue"] = StaticText("Log")
		elif self.what == "s":
			self["key_green"] = StaticText("Clients")
			self["key_yellow"] = StaticText("")
			self["key_blue"] = StaticText("Log")
		elif self.what == "l":
			self["key_green"] = StaticText("Clients")
			self["key_yellow"] = StaticText("Servers")
			self["key_blue"] = StaticText("")
		else:
			self["key_green"] = StaticText("Clients")
			self["key_yellow"] = StaticText("Servers")
			self["key_blue"] = StaticText("Log")	
		self.fieldSizes = []
		self.fs2 = {}
		if config.plugins.caminfo.autoupdate.value:
			self.loop = eTimer()
			self.loop.callback.append(self.showData)
			timeout = config.plugins.caminfo.intervall.value * 1000
			self.loop.start(timeout, False)
		self["actions"] = ActionMap(["OkCancelActions", "ColorActions"],
					{
						"ok": self.showData,
						"cancel": self.exit,
						"red": self.exit,
						"green": self.key_green,
						"yellow": self.key_yellow,
						"blue": self.key_blue
					}, -1)
		self.onLayoutFinish.append(self.showData)
		
	def key_green(self):
		if self.what == "c":
			pass
		else:
			self.what = "c"
			self.showData()
		
	def key_yellow(self):
		if self.what == "s":
			pass
		else:
			self.what = "s"
			self.showData()
	
	def key_blue(self):
		if self.what == "l":
			pass
		else:
			self.what = "l"
			self.showData()
		
	def exit(self):
		if config.plugins.caminfo.autoupdate.value:
			self.loop.stop()
		self.close()
		
	def buildListEntry(self, listentry, heading = False):
		res = [ None ]
		x = 0
		if not HDSKIN:
			self.fieldsize = [ 100, 130, 100, 150, 80, 130 ]
			self.startPos = [ 10, 110, 240, 340, 490, 570 ]
			useFont = 3
		else:
			self.fieldsize = [ 150, 200, 130, 200, 100, 150 ]
			self.startPos = [ 50, 200, 400, 530, 730, 830 ]
			
			useFont = 1
		if isinstance(self.errmsg, tuple):
			useFont = 0  # overrides previous font-size in case of an error message. (if self.errmsg is a tuple, an error occurred which will be displayed instead of regular results
		if not heading:
			status = listentry[len(listentry)-1]
			colour = "0xffffff"
			if status == "OK" or "CONNECTED" or status == "CARDOK":
				colour = "0x389416"
			if status == "NEEDINIT":
				colour = "0xbab329"
			if status == "OFF" or status == "ERROR":
				colour = "0xf23d21"
		else:
			colour = "0xffffff"
		for i in listentry[:-1]:
			xsize = self.fieldsize[x]
			xpos = self.startPos[x]
			res.append( (eListboxPythonMultiContent.TYPE_TEXT, xpos, 0, xsize, 20, useFont, RT_HALIGN_LEFT, i, int(colour, 16)) )
			x += 1
		if heading:
			pos = 19
			res.append( (eListboxPythonMultiContent.TYPE_PIXMAP, 0, pos, self.sizeLH, useFont, LoadPixmap("/usr/share/enigma2/skin_default/div-h.png")))
		return res

	def buildLogListEntry(self, listentry):
		res = [ None ]
		for i in listentry:
			if i.strip() != "" or i is not None:
				res.append( (eListboxPythonMultiContent.TYPE_TEXT, 5, 0, self.sizeLH,14, 2, RT_HALIGN_LEFT, i) )
		return res
		
	def calcSizes(self, entries):
		self.fs2 = {}
		colSize = [ 100, 200, 150, 200, 150, 100 ]
		for h in entries:
			for i, j in enumerate(h[:-1]):
				try:
					self.fs2[i].append(colSize[i])
				except KeyError:
					self.fs2[i] = []
					self.fs2[i].append(colSize[i])
		sizes = []
		for i in self.fs2.keys():
			sizes.append(self.fs2[i])
		return sizes

	def changeScreensize(self, new_height, new_width = None):
		if new_width is None:
			new_width = sizeH
		self.instance.resize(eSize(new_width, new_height))
		fb = getDesktop(0).size()
		new_posY = int(( fb.height() / 2 ) - ( new_height / 2 ))
		x = int( ( fb.width() - sizeH ) / 2 )
		self.instance.move(ePoint(x, new_posY))
		self["output"].resize(eSize(self.sizeLH, new_height - 20))
		self["key_red"].setText(_("Close"))
		if self.what == "c":
			self["key_green"].setText("")
			self["key_yellow"].setText("Servers")
			self["key_blue"].setText("Log")
			self["output"].l.setItemHeight(20)
		elif self.what == "s":
			self["key_green"].setText("Clients")
			self["key_yellow"].setText("")
			self["key_blue"].setText("Log")
			self["output"].l.setItemHeight(20)
		elif self.what == "l":
			self["key_green"].setText("Clients")
			self["key_yellow"].setText("Servers")
			self["key_blue"].setText("")
			self["output"].l.setItemHeight(14)
		else:
			self["key_green"].setText("Clients")
			self["key_yellow"].setText("Servers")
			self["key_blue"].setText("Log")

	def showData(self):
		if self.firstrun:
			data = self.webif_data
			self.firstrun = False
		else:
			data = self.readXML(typ = self.what)
		if not isinstance(data,str):
			out = []
			if self.what != "l":
				heading = ( self.HEAD[self.NAME], self.HEAD[self.PROT], self.HEAD[self.CAID_SRVID],
						self.HEAD[self.SRVNAME], self.HEAD[self.ECMTIME], self.HEAD[self.IP_PORT], "")
				outlist = [ ]
				outlist.append( heading )
				for i in data:
					outlist.append( i )
				self.fieldsize = self.calcSizes(outlist)
				out = [ self.buildListEntry(heading, heading=True)]
				for i in data:
					out.append(self.buildListEntry(i))
			else:
				for i in data:
					if i != "":
						out.append( self.buildLogListEntry( (i,) ))
				#out.reverse()
			ysize = (len(out) + 4 ) * 25
			if self.what == "c":
				self.changeScreensize( ysize )
				self.setTitle("Client Info ( Cam-Version: %s )" % self.getVersion())
			elif self.what == "s":
				self.changeScreensize( ysize )
				self.setTitle("Server Info( Cam-Version: %s )" % self.getVersion())
				
			elif self.what == "l":
				self.changeScreensize( 500 )
				self.setTitle("Cam Log ( Cam-Version: %s )" % self.getVersion())
			self["output"].l.setList(out)
			self["output"].selectionEnabled(False)
		else:
			self.errmsg = (data,)
			if config.plugins.caminfo.autoupdate.value:
				self.loop.stop()
			self.fieldsize = self.calcSizes( [(data,)] )
			ysize = 150
			self.changeScreensize( ysize )
			self.setTitle(_("Error"))
			self["status"].setText(data)
			self["status"].show()
		
class oscEntitlements(Screen, CamInfo):
	global HDSKIN, sizeH
	sizeLH = sizeH - 20	
	skin = """<screen position="center,center" size="%s, 400" title="Client Info" >
			<widget enableWrapAround="1" source="output" render="Listbox" position="10,10" size="%s,400" scrollbarMode="showOnDemand" >
				<convert type="TemplatedMultiContent">
				{"templates":
					{"default": (55,[
							MultiContentEntryText(pos = (0, 1), size = (80, 24), font=0, flags = RT_HALIGN_LEFT, text = 0), # index 0 is caid
							MultiContentEntryText(pos = (90, 1), size = (150, 24), font=0, flags = RT_HALIGN_LEFT, text = 1), # index 1 is csystem
							MultiContentEntryText(pos = (250, 1), size = (40, 24), font=0, flags = RT_HALIGN_LEFT, text = 2), # index 2 is hop 1
							MultiContentEntryText(pos = (290, 1), size = (40, 24), font=0, flags = RT_HALIGN_LEFT, text = 3), # index 3 is hop 2
							MultiContentEntryText(pos = (330, 1), size = (40, 24), font=0, flags = RT_HALIGN_LEFT, text = 4), # index 4 is hop 3
							MultiContentEntryText(pos = (370, 1), size = (40, 24), font=0, flags = RT_HALIGN_LEFT, text = 5), # index 5 is hop 4
							MultiContentEntryText(pos = (410, 1), size = (40, 24), font=0, flags = RT_HALIGN_LEFT, text = 6), # index 6 is hop 5
							MultiContentEntryText(pos = (480, 1), size = (70, 24), font=0, flags = RT_HALIGN_LEFT, text = 7), # index 7 is sum of cards for caid
							MultiContentEntryText(pos = (550, 1), size = (80, 24), font=0, flags = RT_HALIGN_LEFT, text = 8), # index 8 is reshare
							MultiContentEntryText(pos = (0, 25), size = (700, 24), font=1, flags = RT_HALIGN_LEFT, text = 9), # index 9 is providers
													]),
					"HD": (55,[
							MultiContentEntryText(pos = (0, 1), size = (80, 24), font=0, flags = RT_HALIGN_LEFT, text = 0), # index 0 is caid
							MultiContentEntryText(pos = (90, 1), size = (150, 24), font=0, flags = RT_HALIGN_LEFT, text = 1), # index 1 is csystem
							MultiContentEntryText(pos = (250, 1), size = (40, 24), font=0, flags = RT_HALIGN_LEFT, text = 2), # index 2 is hop 1
							MultiContentEntryText(pos = (290, 1), size = (40, 24), font=0, flags = RT_HALIGN_LEFT, text = 3), # index 3 is hop 2
							MultiContentEntryText(pos = (330, 1), size = (40, 24), font=0, flags = RT_HALIGN_LEFT, text = 4), # index 4 is hop 3
							MultiContentEntryText(pos = (370, 1), size = (40, 24), font=0, flags = RT_HALIGN_LEFT, text = 5), # index 5 is hop 4
							MultiContentEntryText(pos = (410, 1), size = (40, 24), font=0, flags = RT_HALIGN_LEFT, text = 6), # index 6 is hop 5
							MultiContentEntryText(pos = (480, 1), size = (70, 24), font=0, flags = RT_HALIGN_LEFT, text = 7), # index 7 is sum of cards for caid
							MultiContentEntryText(pos = (550, 1), size = (80, 24), font=0, flags = RT_HALIGN_LEFT, text = 8), # index 8 is reshare
							MultiContentEntryText(pos = (630, 1), size = (1024, 50), font=1, flags = RT_HALIGN_LEFT, text = 9), # index 9 is providers
						
												]),
					},
					"fonts": [gFont("Regular", 18),gFont("Regular", 14),gFont("Regular", 24),gFont("Regular", 20)],
					"itemHeight": 56
				}
				</convert>
			</widget>
		</screen>""" % ( sizeH, sizeLH)
	def __init__(self, session, reader):
		global HDSKIN, sizeH
		Screen.__init__(self, session)
		self.mlist = oscMenuList([])
		self.cccamreader = reader
		self["output"] = List([ ])
		self["actions"] = ActionMap(["OkCancelActions"],
					{
						"ok": self.showData,
						"cancel": self.exit
					}, -1)
		self.onLayoutFinish.append(self.showData)	
	
	def exit(self):
		self.close()
		
	def buildList(self, data):
		caids = data.keys()
		caids.sort()
		outlist = []
		res = [ ("CAID", "System", "1", "2", "3", "4", "5", "Total", "Reshare", "") ]
		for i in caids:
			csum = 0
			ca_id = i
			csystem = data[i]["system"]
			hops = data[i]["hop"]
			csum += sum(hops)
			creshare = data[i]["reshare"]
			prov = data[i]["provider"]
			if not HDSKIN:
				providertxt = _("Providers: ")
				linefeed = ""
			else:
				providertxt = ""
				linefeed = "\n"
			for j in prov:
				providertxt += "%s - %s%s" % ( j[0], j[1], linefeed )
			res.append( ( 	ca_id,
					csystem,
					str(hops[1]),str(hops[2]), str(hops[3]), str(hops[4]), str(hops[5]), str(csum), str(creshare),
					providertxt[:-1]
					) )
			outlist.append(res)
		return res
			
	def showData(self):
		xmldata_for_reader = self.openWebIF(part = "entitlement", reader = self.cccamreader)
		xdata = ElementTree.XML(xmldata_for_reader[1])
		reader = xdata.find("reader")
		if reader.attrib.has_key("hostaddress"):
			hostadr = reader.attrib["hostaddress"]
			host_ok = True
		else:
			host_ok = False
		cardlist = reader.find("cardlist")
		cardTotal = cardlist.attrib["totalcards"]
		cards = cardlist.findall("card")
		caid = {}
		for i in cards:
			ccaid = i.attrib["caid"]
			csystem = i.attrib["system"]
			creshare = i.attrib["reshare"]
			if not host_ok:
				hostadr = i.find("hostaddress").text
			chop = int(i.attrib["hop"])
			if chop > 5:
				chop = 5
			if caid.has_key(ccaid):
				if caid[ccaid].has_key("hop"):
					caid[ccaid]["hop"][chop] += 1
				else:
					caid[ccaid]["hop"] = [ 0, 0, 0, 0, 0, 0 ]
					caid[ccaid]["hop"][chop] += 1
				caid[ccaid]["reshare"] = creshare
				caid[ccaid]["provider"] = [ ]
				provs = i.find("providers")
				for prov in provs.findall("provider"):
					caid[ccaid]["provider"].append( (prov.attrib["provid"], prov.text) )
				caid[ccaid]["system"] = csystem
			else:
				caid[ccaid] = {}
				if caid[ccaid].has_key("hop"):
					caid[ccaid]["hop"][chop] += 1
				else:
					caid[ccaid]["hop"] = [ 0, 0, 0, 0, 0, 0]
					caid[ccaid]["hop"][chop] += 1
				caid[ccaid]["reshare"] = creshare
				caid[ccaid]["provider"] = [ ]
				provs = i.find("providers")
				for prov in provs.findall("provider"):
					caid[ccaid]["provider"].append( (prov.attrib["provid"], prov.text) )
				caid[ccaid]["system"] = csystem
		result = self.buildList(caid)
		if HDSKIN:
			self["output"].setStyle("HD")
		else:
			self["output"].setStyle("default")
		self["output"].setList(result)
		title = [ _("Reader"), self.cccamreader, _("Cards:"), cardTotal, "Server:", hostadr ]
		self.setTitle( " ".join(title))
			

class oscReaderStats(Screen, CamInfo):
	global HDSKIN, sizeH
	sizeLH = sizeH - 20
	skin = """<screen position="center,center" size="%s, 400" title="Client Info" >
			<widget enableWrapAround="1" source="output" render="Listbox" position="10,10" size="%s,400" scrollbarMode="showOnDemand" >
				<convert type="TemplatedMultiContent">
				{"templates":
					{"default": (25,[
							MultiContentEntryText(pos = (0, 1), size = (100, 24), font=0, flags = RT_HALIGN_LEFT, text = 0), # index 0 is caid
							MultiContentEntryText(pos = (100, 1), size = (50, 24), font=0, flags = RT_HALIGN_LEFT, text = 1), # index 1 is csystem
							MultiContentEntryText(pos = (150, 1), size = (150, 24), font=0, flags = RT_HALIGN_LEFT, text = 2), # index 2 is hop 1
							MultiContentEntryText(pos = (300, 1), size = (60, 24), font=0, flags = RT_HALIGN_LEFT, text = 3), # index 3 is hop 2
							MultiContentEntryText(pos = (360, 1), size = (60, 24), font=0, flags = RT_HALIGN_LEFT, text = 4), # index 4 is hop 3
							MultiContentEntryText(pos = (420, 1), size = (80, 24), font=0, flags = RT_HALIGN_LEFT, text = 5), # index 5 is hop 4
							MultiContentEntryText(pos = (510, 1), size = (80, 24), font=0, flags = RT_HALIGN_LEFT, text = 6), # index 6 is hop 5
							MultiContentEntryText(pos = (590, 1), size = (80, 24), font=0, flags = RT_HALIGN_LEFT, text = 7), # index 7 is sum of cards for caid
							]),
					"HD": (25,[
							MultiContentEntryText(pos = (0, 1), size = (200, 24), font=1, flags = RT_HALIGN_LEFT, text = 0), # index 0 is caid
							MultiContentEntryText(pos = (200, 1), size = (70, 24), font=1, flags = RT_HALIGN_LEFT, text = 1), # index 1 is csystem
							MultiContentEntryText(pos = (290, 1), size = (220, 24), font=1, flags = RT_HALIGN_LEFT, text = 2), # index 2 is hop 1
							MultiContentEntryText(pos = (510, 1), size = (120, 24), font=1, flags = RT_HALIGN_LEFT, text = 3), # index 3 is hop 2
							MultiContentEntryText(pos = (630, 1), size = (130, 24), font=1, flags = RT_HALIGN_LEFT, text = 4), # index 4 is hop 3
							MultiContentEntryText(pos = (760, 1), size = (130, 24), font=1, flags = RT_HALIGN_LEFT, text = 5), # index 5 is hop 4
							MultiContentEntryText(pos = (890, 1), size = (170, 24), font=1, flags = RT_HALIGN_LEFT, text = 6), # index 6 is hop 5
							MultiContentEntryText(pos = (1060, 1), size = (100, 24), font=1, flags = RT_HALIGN_LEFT, text = 7), # index 7 is sum of cards for caid
							]),
					},
					"fonts": [gFont("Regular", 14),gFont("Regular", 18),gFont("Regular", 24),gFont("Regular", 20)],
					"itemHeight": 26
				}
				</convert>
			</widget>
		</screen>""" % ( sizeH, sizeLH)
	def __init__(self, session, reader):
		global HDSKIN, sizeH
		Screen.__init__(self, session)
		if reader == "all":
			self.allreaders = True
		else:
			self.allreaders = False
		self.reader = reader
		self.mlist = oscMenuList([])
		self["output"] = List([ ])
		self["actions"] = ActionMap(["OkCancelActions"],
					{
						"ok": self.showData,
						"cancel": self.exit
					}, -1)
		self.onLayoutFinish.append(self.showData)	
	
	def exit(self):
		self.close()
		
	def buildList(self, data):
		caids = data.keys()
		caids.sort()
		outlist = []
		res = [ ("CAID", "System", "1", "2", "3", "4", "5", "Total", "Reshare", "") ]
		for i in caids:
			csum = 0
			ca_id = i
			csystem = data[i]["system"]
			hops = data[i]["hop"]
			csum += sum(hops)
			creshare = data[i]["reshare"]
			prov = data[i]["provider"]
			if not HDSKIN:
				providertxt = _("Providers: ")
				linefeed = ""
			else:
				providertxt = ""
				linefeed = "\n"
			for j in prov:
				providertxt += "%s - %s%s" % ( j[0], j[1], linefeed )
			res.append( ( 	ca_id,
					csystem,
					str(hops[1]),str(hops[2]), str(hops[3]), str(hops[4]), str(hops[5]), str(csum), str(creshare),
					providertxt[:-1]
					) )
			outlist.append(res)
		return res

	def sortData(self, datalist, sort_col, reverse = False):
		return sorted(datalist, key=itemgetter(sort_col), reverse = reverse)
		
	def showData(self):
		readers = self.getReaders()
		result = []
		title2 = ""
		for i in readers:
			xmldata = self.openWebIF(part = "readerstats", reader = i[1])
			emm_wri = emm_ski = emm_blk = emm_err = ""
			if xmldata[0]:
				xdata = ElementTree.XML(xmldata[1])
				rdr = xdata.find("reader")
#					emms = rdr.find("emmstats")
#					if emms.attrib.has_key("totalwritten"):
#						emm_wri = emms.attrib["totalwritten"]
#					if emms.attrib.has_key("totalskipped"):
#						emm_ski = emms.attrib["totalskipped"]
#					if emms.attrib.has_key("totalblocked"):
#						emm_blk = emms.attrib["totalblocked"]
#					if emms.attrib.has_key("totalerror"):
#						emm_err = emms.attrib["totalerror"]
					
				ecmstat = rdr.find("ecmstats")
				totalecm = ecmstat.attrib["totalecm"]
				ecmcount = ecmstat.attrib["count"]
				lastacc = ecmstat.attrib["lastaccess"]
				ecm = ecmstat.findall("ecm")
				if ecmcount > 0:
					for j in ecm:
						caid = j.attrib["caid"]
						channel = j.attrib["channelname"]
						avgtime = j.attrib["avgtime"]
						lasttime = j.attrib["lasttime"]
						retcode = j.attrib["rc"]
						rcs = j.attrib["rcs"]
						num = j.text
						if rcs == "found":
							avg_time = str(float(avgtime) / 1000)[:5]
							last_time = str(float(lasttime) / 1000)[:5]
							if j.attrib.has_key("lastrequest") and j.attrib["lastrequest"] != "":
								lastreq = j.attrib["lastrequest"]
								try:
									last_req = lastreq.split("T")[1][:-5]
								except IndexError:
									last_req = time.strftime("%H:%M:%S",time.localtime(float(lastreq)))
							else:
									last_req = _("never")
						else:
							avg_time = last_time = last_req = ""
						if self.allreaders:
							result.append( (i[1], caid, channel, avg_time, last_time, rcs, last_req, int(num)) )
							title2 = _("( All readers)")
						else:
							if i[1] == self.reader:
								result.append( (i[1], caid, channel, avg_time, last_time, rcs, last_req, int(num)) )
							title2 =_("(Show only reader:") + "%s )" % self.reader

		outlist = self.sortData(result, 7, True)
		out = [ ( _("Label"), _("CAID"), _("Channel"), _("ECM avg"), _("ECM last"), _("Status"), _("Last Req."), _("Total") ) ]
		for i in outlist:
			out.append( (i[0], i[1], i[2], i[3], i[4], i[5], i[6], str(i[7])) )
			
		
		if HDSKIN:
			self["output"].setStyle("HD")
		else:
			self["output"].setStyle("default")
		self["output"].setList(out)
		title = [ _("Reader Statistics"), title2 ]
		self.setTitle( " ".join(title))

		

class OscamInfoConfigScreen(Screen, ConfigListScreen):
	skin = """
		<screen name="OscamInfoConfigScreen" position="center,center" size="660,450" title="OScamInfo Config">
			<ePixmap pixmap="skin_default/buttons/red.png" position="0,0" size="140,40" alphatest="on" />
			<ePixmap pixmap="skin_default/buttons/green.png" position="140,0" size="140,40" alphatest="on" />
			<widget source="key_red" render="Label" position="0,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#9f1313" transparent="1" />
			<widget source="key_green" render="Label" position="140,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#1f771f" transparent="1" />
			<widget enableWrapAround="1" name="config" position="5,50" size="650,360" scrollbarMode="showOnDemand" zPosition="1"/>
			<widget enableWrapAround="1" name="status" render="Label" position="10,380" zPosition="1" size="640,70" font="Regular;16" halign="center" valign="center" transparent="1" />
		</screen>"""
	
	def __init__(self, session, msg = None):
		Screen.__init__(self, session)
		self.session = session
		if msg is not None:
			self.msg = "Error:\n%s" % msg
		else:
			self.msg = ""
		self.camconfig = [ ]
		self["key_red"] = StaticText(_("Cancel"))
		self["key_green"] = StaticText(_("OK"))
		self["status"] = StaticText(self.msg)
		self["config"] = ConfigList(self.camconfig)
		self["actions"] = ActionMap(["SetupActions", "ColorActions"],
		{
			"red": self.cancel,
			"green": self.save,
			"save": self.save,
			"cancel": self.cancel,
			"ok": self.save,
		}, -2)
		ConfigListScreen.__init__(self, self.camconfig, session = self.session)
		self.createSetup()
		config.plugins.caminfo.userdatafromconf.addNotifier(self.elementChanged, initial_call = False)
		config.plugins.caminfo.autoupdate.addNotifier(self.elementChanged, initial_call = False)
		config.plugins.caminfo.ActivateCam.addNotifier(self.elementChanged, initial_call = False)
		config.plugins.caminfo.CamSelect.addNotifier(self.elementChanged, initial_call = False)
		self.onLayoutFinish.append(self.layoutFinished)

	def elementChanged(self, instance):
		self.createSetup()
		try:
			self["config"].l.setList(self.camconfig)
		except KeyError:
			pass
	
	def layoutFinished(self):
		self.setTitle(_("Cam Info - Configuration"))
		self["config"].l.setList(self.camconfig)

	def createSetup(self):
		self.camconfig = []
		self.camconfig.append(getConfigListEntry(_("Activate local Cam(s)"), config.plugins.caminfo.ActivateCam))
		if config.plugins.caminfo.ActivateCam.value:
			self.camconfig.append(getConfigListEntry(_("Active Cam"), config.plugins.caminfo.CamSelect))
			if config.plugins.caminfo.CamSelect.value == "oscam":
				self.camconfig.append(getConfigListEntry(_("Read Userdata from oscam.conf"), config.plugins.caminfo.userdatafromconf))
				if not config.plugins.caminfo.userdatafromconf.value:
					self.camconfig.append(getConfigListEntry(_("IP-Address"), config.plugins.caminfo.ip))
					self.camconfig.append(getConfigListEntry("Port", config.plugins.caminfo.port))
					self.camconfig.append(getConfigListEntry(_("Username (httpuser)"), config.plugins.caminfo.username))
					self.camconfig.append(getConfigListEntry(_("Password (httpwd)"), config.plugins.caminfo.password))
					self.camconfig.append(getConfigListEntry(_("Automatically update Client/Server View?"), config.plugins.caminfo.autoupdate))
				if config.plugins.caminfo.autoupdate.value:
					self.camconfig.append(getConfigListEntry(_("Update interval (in seconds)"), config.plugins.caminfo.intervall))
			self.camconfig.append(getConfigListEntry(_("Local-Cam-Binary-Path"), config.plugins.caminfo.CamBinaryPath))
			self.camconfig.append(getConfigListEntry(_("Local-Cam-Config-Path"), config.plugins.caminfo.CamConfigPath))
			self.camconfig.append(getConfigListEntry(_("Autostart Cam on boot"), config.plugins.caminfo.CamAutostart))

	def camselect(self):
		global CamSelect_old
		bindir = config.plugins.caminfo.CamBinaryPath.value
		confdir = config.plugins.caminfo.CamConfigPath.value
		if config.plugins.caminfo.ActivateCam.value:
			CamSelect = config.plugins.caminfo.CamSelect.value
			isRunning = system("pidof %s" % CamSelect)
			if isRunning != 0:
				system("echo 'stopping Old-Cam now...'; echo '';mycams='oscam CCcam2_2_1 Scam gbox camd3 incubusCamd mbox mgcamd';for i in $mycams;do if pidof $i > /dev/null;then kill `pidof $i`;fi;done;for i in $mycams;do if pidof $i > /dev/null;then kill -9 `pidof $i`;fi;done")
				if CamSelect == "oscam":
					cmd = "(echo 'starting OSCam now...'; echo '';%s/%s -b -c %s) &" % (bindir, CamSelect, confdir)
					system(cmd)
#					if os.path.exists("/etc/rcS.d") and config.plugins.caminfo.CamAutostart.value:
#						cmd = "echo '(sleep 20;echo 'starting OSCam now...'; echo '';%s/%s -b -c %s) &' > /etc/rcS.d/S80Softcam; chmod 755 /etc/rcS.d/S80Softcam" % (bindir, CamSelect, confdir)
#						system(cmd)
				elif CamSelect == "CCcam2_2_1":
					cmd = "(echo 'starting CCcam2_2_1 now...'; echo '';%s/%s -C %s/CCcam.cfg) &" % (bindir, CamSelect, confdir)
					system(cmd)
				elif CamSelect == "Scam":
					cmd = "(echo 'starting Scam now...'; echo '';%s/%s) &" % (bindir, CamSelect)
					system(cmd)
				elif CamSelect == "camd3":
					cmd = "(echo 'starting camd3 now...'; echo '';%s/%s %s/camd3.config) &" % (bindir, CamSelect, confdir)
					system(cmd)
				elif CamSelect == "gbox":
					cmd = "(echo 'starting gbox now...'; echo '';%s/%s) &" % (bindir, CamSelect)
					system(cmd)
				elif CamSelect == "incubusCamd":
					cmd = "(echo 'starting incubusCamd now...'; echo '';%s/%s) &" % (bindir, CamSelect)
					system(cmd)
				elif CamSelect == "mbox":
					cmd = "(echo 'starting mbox now...'; echo '';%s/%s) &" % (bindir, CamSelect)
					system(cmd)
				elif CamSelect == "mgcamd":
					cmd = "(echo 'starting mgcamd now...'; echo '';%s/%s) &" % (bindir, CamSelect)
					system(cmd)
				self.session.open(MessageBox, config.plugins.caminfo.CamSelect.value + (" activated!"), MessageBox.TYPE_INFO, timeout=3)
				CamSelect_old = CamSelect

		elif config.plugins.caminfo.ActivateCam.value is False:
			if fileExists("/etc/rcS.d/S80Softcam"):
				cmd = "rm /etc/rcS.d/S80Softcam"
				system(cmd)
			CamSelect = config.plugins.caminfo.CamSelect.value
			isRunning = system("pidof %s" % CamSelect)
			if isRunning == 0:
				system("echo 'stopping Old-Cam now...'; echo '';mycams='oscam CCcam2_2_1 Scam gbox camd3 incubusCamd mbox mgcamd';for i in $mycams;do if pidof $i > /dev/null;then kill `pidof $i`;fi;done;for i in $mycams;do if pidof $i > /dev/null;then kill -9 `pidof $i`;fi;done")
				self.session.open(MessageBox, (" All Cam's deactivated!"), MessageBox.TYPE_INFO, timeout=3)

	def save(self):	
		for x in self.camconfig:
			if config.plugins.caminfo.ActivateCam.value is False:
				config.plugins.caminfo.CamAutostart.value = False
			x[1].save()
		configfile.save()
		self.camselect()
		self.close()
		
	def cancel(self):
		for x in self.camconfig:
			x[1].cancel()
		self.close()

class ProxyServerConfigScreen(Screen, ConfigListScreen):
	skin = """
		<screen name="ProxyServerConfigScreen" position="center,center" size="660,450" title="Proxy Server Setup">
			<ePixmap pixmap="skin_default/buttons/red.png" position="0,0" size="140,40" alphatest="on" />
			<ePixmap pixmap="skin_default/buttons/green.png" position="140,0" size="140,40" alphatest="on" />
			<widget source="key_red" render="Label" position="0,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#9f1313" transparent="1" />
			<widget source="key_green" render="Label" position="140,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#1f771f" transparent="1" />
			<widget enableWrapAround="1" name="config" position="5,50" size="650,360" scrollbarMode="showOnDemand" zPosition="1"/>
			<widget enableWrapAround="1" name="status" render="Label" position="10,380" zPosition="1" size="640,70" font="Regular;16" halign="center" valign="center" transparent="1" />
		</screen>"""
	
	def __init__(self, session, msg = None):
		Screen.__init__(self, session)
		self.session = session
		if msg is not None:
			self.msg = "Error:\n%s" % msg
		else:
			self.msg = ""
		self.proxyconfig = [ ]
		self["key_red"] = StaticText(_("Cancel"))
		self["key_green"] = StaticText(_("OK"))
		self["status"] = StaticText(self.msg)
		self["config"] = ConfigList(self.proxyconfig)
		self["actions"] = ActionMap(["SetupActions", "ColorActions"],
		{
			"red": self.cancel,
			"green": self.save,
			"save": self.save,
			"cancel": self.cancel,
			"ok": self.save,
		}, -2)
		ConfigListScreen.__init__(self, self.proxyconfig, session = self.session)
		self.ProxySetup()
		config.plugins.caminfo.restartServerCam.addNotifier(self.elementChanged, initial_call = False)
		self.onLayoutFinish.append(self.layoutFinished)

	def elementChanged(self, instance):
		self.ProxySetup()
		try:
			self["config"].l.setList(self.proxyconfig)
		except KeyError:
			pass
	
	def layoutFinished(self):
		self.setTitle(_("ProxyServer - Configuration"))
		self["config"].l.setList(self.proxyconfig)

	def ProxySetup(self):
		self.proxyconfig = []
		self.proxyconfig.append(getConfigListEntry(_("Activate Server-OSCam-Restart-Option?"), config.plugins.caminfo.restartServerCam))
		if config.plugins.caminfo.restartServerCam.value:
			self.proxyconfig.append(getConfigListEntry(_("Server-IP-Address"), config.plugins.caminfo.serverip))

	def save(self):	
		for x in self.proxyconfig:
			x[1].save()
		configfile.save()
		self.close()
		
	def cancel(self):
		for x in self.proxyconfig:
			x[1].cancel()
		self.close()

class ShowOSCamInfoScreen(Screen, ConfigListScreen):
	skin = """
		<screen position="center,center" size="400, 300" title="Show OSCam Infos" >
			<widget enableWrapAround="1" name="oscInfomenu" position="10,10" size="380,280" scrollbarMode="showOnDemand" />
		</screen>"""
	
	def __init__(self, session):
		Screen.__init__(self, session)
		self.session = session
		self.menu = [ _("Show /tmp/ecm.info"), _("Show Clients"), _("Show Readers/Proxies"), _("Show Log"), _("Card infos (CCcam-Reader)"), _("ECM Statistics"), _("Restart Reader")] 
		self.osc = CamInfo()
		self["oscInfomenu"] = oscMenuList([])
		self["actions"] = NumberActionMap(["OkCancelActions", "InputActions", "ColorActions"],
					{
						"ok": self.ok,
						"cancel": self.exit,
						"red": self.red,
						"green": self.green,
						"yellow": self.yellow,
						"blue": self.blue,
						"1": self.keyNumberGlobal,
						"2": self.keyNumberGlobal,
						"3": self.keyNumberGlobal,
						"4": self.keyNumberGlobal,
						"5": self.keyNumberGlobal,
						"6": self.keyNumberGlobal,
						"7": self.keyNumberGlobal,
						"8": self.keyNumberGlobal,
						"9": self.keyNumberGlobal,
						"0": self.keyNumberGlobal,
						"up": self.up,
						"down": self.down
						}, -1)	
		self.onLayoutFinish.append(self.showMenu)
	
	def ok(self):
		selected = self["oscInfomenu"].getSelectedIndex()
		self.goEntry(selected)
	def cancel(self):
		self.close()
	def exit(self):
		self.close()
	def keyNumberGlobal(self, num):
		if num == 0:
			numkey = 10
		else:
			numkey = num
		if numkey < len(self.menu) - 3:
			self["oscInfomenu"].moveToIndex(numkey + 3)
			self.goEntry(numkey + 3)

	def red(self):
		self["oscInfomenu"].moveToIndex(0)
		self.goEntry(0)
	def green(self):
		self["oscInfomenu"].moveToIndex(1)
		self.goEntry(1)
	def yellow(self):
		self["oscInfomenu"].moveToIndex(2)
		self.goEntry(2)
	def blue(self):
		self["oscInfomenu"].moveToIndex(3)
		self.goEntry(3)
	def up(self):
		pass
	def down(self):
		pass
	def goEntry(self, entry):
		if entry == 0: # Show /tmp/ecm.info
			if os.path.exists("/tmp/ecm.info"):
					self.session.open(oscECMInfo)
			else:
				pass
		elif entry == 1: # Show clients
			if config.plugins.caminfo.userdatafromconf.value:
				if self.osc.confPath() is None:
					config.plugins.caminfo.userdatafromconf.value = False
					config.plugins.caminfo.userdatafromconf.save()
					self.session.openWithCallback(self.ErrMsgCallback, MessageBox, _("File oscam.conf not found.\nPlease enter username/password manually."), MessageBox.TYPE_ERROR)
				else:
					s = self.session.open(oscInfo, "c")
					if isinstance(s.errmsg, tuple):
						print s.errmsg[0]
						#self.session.open(MessageBox, s.errmsg[0], MessageBox.TYPE_ERROR, timeout = 10)
			else:
				s = self.session.open(oscInfo, "c")
				if isinstance(s.errmsg, tuple):
					print s.errmsg[0]
					#	self.session.close(oscInfo.getInstance())
					#	self.session.open(MessageBox, s.errmsg[0], MessageBox.TYPE_ERROR, timeout = 10)
		elif entry == 2: # Show Servers
			if config.plugins.caminfo.userdatafromconf.value:
				if self.osc.confPath() is None:
					config.plugins.caminfo.userdatafromconf.value = False
					config.plugins.caminfo.userdatafromconf.save()
					self.session.openWithCallback(self.ErrMsgCallback, MessageBox, _("File oscam.conf not found.\nPlease enter username/password manually."), MessageBox.TYPE_ERROR)
				else:
					self.session.open(oscInfo, "s")
			else:
				self.session.open(oscInfo, "s")
		elif entry == 3: # Show log 
			if config.plugins.caminfo.userdatafromconf.value:
				if self.osc.confPath() is None:
					config.plugins.caminfo.userdatafromconf.value = False
					config.plugins.caminfo.userdatafromconf.save()
					self.session.openWithCallback(self.ErrMsgCallback, MessageBox, _("File oscam.conf not found.\nPlease enter username/password manually."), MessageBox.TYPE_ERROR)
				else:
					self.session.open(oscInfo, "l")
			else:
				self.session.open(oscInfo, "l")
		elif entry == 4: # CCcam Card information
			osc = CamInfo()
			reader = osc.getReaders("cccam")  # get list of available CCcam-Readers
			if isinstance(reader, list):
				if len(reader) == 1:
					self.session.open(oscEntitlements, reader[0][1])
				else:
					self.callbackmode = "cccam"
					self.session.openWithCallback(self.chooseReaderCallback, ChoiceBox, title = _("Please choose CCcam-Reader"), list=reader)
			elif isinstance(reader, str):
				self.showErrorMessage(reader)
			
		elif entry == 5: # ECM Statistics
			osc = CamInfo()
			reader = osc.getReaders()
			if reader is not None:
				if isinstance(reader, list):
					reader.append( ("All", "all") )
					if len(reader) == 1:
						self.session.open(oscReaderStats, reader[0][1])
					else:
						self.callbackmode = "readers"
						self.session.openWithCallback(self.chooseReaderCallback, ChoiceBox, title = _("Please choose reader"), list=reader)
				elif isinstance(reader, str):
					self.showErrorMessage(reader)
		elif entry == 6:
			osc = CamInfo()
			reader = osc.getReaders()
			if reader is not None:
				if isinstance(reader, list):
					if len(reader) == 1:
						self.session.open(oscReaderStats, reader[0][1])
					else:
						self.callbackmode = "restart"
						self.osc = osc
						self.session.openWithCallback(self.chooseReaderCallback, ChoiceBox, title = _("Please choose reader"), list=reader)
				elif isinstance(reader, str):
					self.showErrorMessage(reader)

	def chooseReaderCallback(self, retval):
		print retval
		if retval is not None:
			if self.callbackmode == "cccam":
				self.session.open(oscEntitlements, retval[1])
			elif self.callbackmode == "restart":
				d = self.osc.openWebIF(reader="%s" % retval[1], cmd = "restart")
			else:
				self.session.open(oscReaderStats, retval[1])
				
	def ErrMsgCallback(self, retval):
		print retval
		self.session.open(OscamInfoConfigScreen)
		
	def buildMenu(self, mlist):
		keys = ["red", "green", "yellow", "blue", "1", "2", "3", "4", "5", "6", "7", "8", "9", "0", ""]
		menuentries = []
		y = 0
		for x in mlist:
			res = [ x ]
			if x.startswith("--"):
				png = LoadPixmap("/usr/share/enigma2/skin_default/div-h.png")
				if png is not None:
					res.append((eListboxPythonMultiContent.TYPE_PIXMAP, 10,0,360, 2, png))
					res.append((eListboxPythonMultiContent.TYPE_TEXT, 45, 3, 800, 25, 0, RT_HALIGN_LEFT, x[2:]))
					png2 = LoadPixmap("/usr/share/enigma2/skin_default/buttons/key_" + keys[y] + ".png")
					if png2 is not None:
						res.append((eListboxPythonMultiContent.TYPE_PIXMAP_ALPHATEST, 5, 3, 35, 25, png2))
			else:
				res.append((eListboxPythonMultiContent.TYPE_TEXT, 45, 00, 800, 25, 0, RT_HALIGN_LEFT, x))
				png2 = LoadPixmap("/usr/share/enigma2/skin_default/buttons/key_" + keys[y] + ".png")
				if png2 is not None:
					res.append((eListboxPythonMultiContent.TYPE_PIXMAP_ALPHATEST, 5, 0, 35, 25, png2))
			menuentries.append(res)
			if y < len(keys) - 1:
				y += 1
		return menuentries
	def showMenu(self):
		entr = self.buildMenu(self.menu)
		self.setTitle(_("Show OSCam Info Menu"))
		self["oscInfomenu"].l.setList(entr)
		self["oscInfomenu"].moveToIndex(0)
		
	def showErrorMessage(self, errmsg):
		self.session.open(MessageBox, errmsg, MessageBox.TYPE_ERROR, timeout = 10)

def cam_autostart(session):
	global CamSelect_old
	bindir = config.plugins.caminfo.CamBinaryPath.value
	confdir = config.plugins.caminfo.CamConfigPath.value
	if config.plugins.caminfo.CamAutostart.value:
		if config.plugins.caminfo.ActivateCam.value:
			CamSelect = config.plugins.caminfo.CamSelect.value
			isRunning = system("pidof %s" % CamSelect)
			if isRunning != 0:
				if CamSelect == "oscam":
					cmd = "(echo 'starting OSCam now...'; echo '';%s/%s -b -c %s) &" % (bindir, CamSelect, confdir)
					system(cmd)
				elif CamSelect == "CCcam2_2_1":
					cmd = "(echo 'starting CCcam2_2_1 now...'; echo '';%s/%s -C %s/CCcam.cfg) &" % (bindir, CamSelect, confdir)
					system(cmd)
				elif CamSelect == "Scam":
					cmd = "(echo 'starting Scam now...'; echo '';%s/%s) &" % (bindir, CamSelect)
					system(cmd)
				elif CamSelect == "camd3":
					cmd = "(echo 'starting camd3 now...'; echo '';%s/%s %s/camd3.config) &" % (bindir, CamSelect, confdir)
					system(cmd)
				elif CamSelect == "gbox":
					cmd = "(echo 'starting gbox now...'; echo '';%s/%s) &" % (bindir, CamSelect)
					system(cmd)
				elif CamSelect == "incubusCamd":
					cmd = "(echo 'starting incubusCamd now...'; echo '';%s/%s) &" % (bindir, CamSelect)
					system(cmd)
				elif CamSelect == "mbox":
					cmd = "(echo 'starting mbox now...'; echo '';%s/%s) &" % (bindir, CamSelect)
					system(cmd)
				elif CamSelect == "mgcamd":
					cmd = "(echo 'starting mgcamd now...'; echo '';%s/%s) &" % (bindir, CamSelect)
					system(cmd)
				CamSelect_old = CamSelect

def main(session, **kwargs):
	global HDSKIN, sizeH
	m = session.open(CamInfoMenu)

def autostart(reason, **kwargs):
	if kwargs.has_key("session"):
		global global_session
		global_session = kwargs["session"]
		return
	if reason == 0:
		cam_autostart(global_session)
	elif reason == 1:
		global_session = None

def Plugins(**kwargs):
	return [ PluginDescriptor(name="OScamInfo", description=_("All you need for Cam"), where = PluginDescriptor.WHERE_PLUGINMENU, fnc=main),
		PluginDescriptor(name="OScamInfo", where = PluginDescriptor.WHERE_EXTENSIONSMENU, fnc=main),
		PluginDescriptor(where=[PluginDescriptor.WHERE_SESSIONSTART, PluginDescriptor.WHERE_AUTOSTART], fnc=autostart) ]
