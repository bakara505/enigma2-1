# uncompyle6 version 3.7.4
# Python bytecode 2.7 (62211)
# Decompiled from: Python 2.7.17 (default, Sep 30 2020, 13:38:04) 
# [GCC 7.5.0]
# Embedded file name: /usr/lib/enigma2/python/Screens/ScriptRunner.py
# Compiled at: 2022-02-10 15:21:47
from . import _
from Plugins.Plugin import PluginDescriptor
from Screens.Screen import Screen
from Screens.Console import Console
from Screens.ChoiceBox import ChoiceBox
from Screens.MessageBox import MessageBox
from Components.ActionMap import ActionMap, HelpableActionMap
from Components.Label import Label
from Components.Language import language
from Components.Button import Button
from Components.MenuList import MenuList
from Components.Sources.List import List
from Screens.Standby import TryQuitMainloop
from Tools.Directories import resolveFilename, SCOPE_PLUGINS, SCOPE_CURRENT_SKIN
from os import listdir, remove, mkdir, path, access, X_OK, chmod
import datetime, time

class ScriptRunner(Screen):
    skin = '<screen name="ScriptRunner" position="center,center" size="560,400" title="Script Runner" flags="wfBorder" >\n\t\t<ePixmap pixmap="skin_default/buttons/red.png" position="0,0" size="140,40" alphatest="on" />\n\t\t<ePixmap pixmap="skin_default/buttons/green.png" position="140,0" size="140,40" alphatest="on" />\n\t\t<widget name="key_red" position="0,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#9f1313" transparent="1" />\n\t\t<widget name="key_green" position="140,0" zPosition="1" size="140,40" font="Regular;20" halign="center" valign="center" backgroundColor="#1f771f" transparent="1" />\n\t\t<widget name="lab1" position="0,50" size="560,50" font="Regular; 20" zPosition="2" transparent="0" halign="center"/>\n\t\t<widget name="list" position="10,105" size="540,300" scrollbarMode="showOnDemand" />\n\t\t<applet type="onLayoutFinish">\n\t\t\tself["list"].instance.setItemHeight(25)\n\t\t</applet>\n\t</screen>'

    def __init__(self, session):
        Screen.__init__(self, session)
        Screen.setTitle(self, _('Job Manager'))
        self['lab1'] = Label()
        self.list = []
        self.populate_List()
        self['list'] = MenuList(self.list)
        self['myactions'] = ActionMap(['ColorActions', 'OkCancelActions', 'DirectionActions'], {'cancel': self.close, 'red': self.close, 
           'green': self.runscript, 
           'ok': self.runscript}, -1)
        self['key_red'] = Button(_('Close'))
        self['key_green'] = Button(_('Run'))

    def populate_List(self):
        if not path.exists('/usr/scripts'):
            mkdir('/usr/scripts', 493)
        self['lab1'].setText(_('Select a script to run:'))
        del self.list[:]
        f = listdir('/usr/scripts')
        for line in f:
            parts = line.split()
            pkg = parts[0]
            if pkg.find('.sh') >= 0:
                self.list.append(pkg)

        self.list.sort()

    def runscript(self):
        self.sel = self['list'].getCurrent()
        if self.sel:
            message = _('Are you ready to run the script ?')
            ybox = self.session.openWithCallback(self.Run, MessageBox, message, MessageBox.TYPE_YESNO)
            ybox.setTitle(_('Run Confirmation'))
        else:
            self.session.open(MessageBox, _('You have no script to run.'), MessageBox.TYPE_INFO, timeout=10)

    def Run(self, answer):
        if answer is True:
            if not access('/usr/scripts/' + self.sel, X_OK):
                chmod('/usr/scripts/' + self.sel, 493)
            cmd1 = '. /usr/scripts/' + self.sel
            self.session.open(Console, title=self.sel, cmdlist=[cmd1], closeOnSuccess=False)

    def myclose(self):
        self.close()