# Embedded file name: /usr/lib/enigma2/python/Screens/Lan.py
from Plugins.Plugin import PluginDescriptor
from Screens.Screen import Screen
from Screens.MessageBox import MessageBox
from Screens.ChoiceBox import ChoiceBox
from Screens.Standby import TryQuitMainloop
from enigma import evfd, eTimer
from time import localtime, strftime, sleep
from Components.Console import Console
from Tools.Directories import fileExists, resolveFilename, SCOPE_LANGUAGE, SCOPE_PLUGINS
from os import environ, statvfs
from Components.ActionMap import ActionMap
from Components.config import *
from Components.ConfigList import ConfigList, ConfigListScreen
from Components.Label import Label
from Components.Language import language
from Components.Sources.StaticText import StaticText
import os
from Tools.HardwareInfo import HardwareInfo
from time import sleep
import gettext
lang = language.getLanguage()
environ['LANGUAGE'] = lang[:2]
gettext.bindtextdomain('enigma2', resolveFilename(SCOPE_LANGUAGE))
gettext.textdomain('enigma2')
gettext.bindtextdomain('Systemoptions', '%s%s' % (resolveFilename(SCOPE_PLUGINS), 'usr/share/locale/'))

def _(txt):
    t = gettext.dgettext('Systemoptions', txt)
    if t == txt:
        t = gettext.gettext(txt)
    return t


def translateBlock(block):
    for x in TranslationHelper:
        if block.__contains__(x[0]):
            block = block.replace(x[0], x[1])

    return block


pll0 = '/etc/cpu_frequ/pll0_ndiv_mdiv'
stb = HardwareInfo().get_device_name()
config.plugins.systemoptions = ConfigSubsection()
config.plugins.systemoptions.wlan = ConfigSelection(default='0', choices=[('0', 'none'),
 ('8712u', 'RTL8712U'),
 ('8188eu', 'RTL8188EU'),
 ('8192cu', 'RTL8192CU'),
 ('8192du', 'RTL8192DU'),
 ('8192eu', 'RTL8192EU'),
 ('mt7601Usta', 'MT7601U'),
 ('rt2870sta', 'RT2870STA'),
 ('rt3070sta', 'RT3070STA'),
 ('rt5370sta', 'RT5370STA')])
config.plugins.systemoptions.autologin = ConfigSelection(default='yes', choices=[('yes', _('yes')), ('no', _('no'))])
config.plugins.systemoptions.swap = ConfigSelection(default='no', choices=[('yes', _('yes')), ('no', _('no'))])
config.plugins.systemoptions.swapsize = ConfigSelection(default='32768', choices=[('32768', _('32 Mbyte')), ('65536', _('64 Mbyte')), ('131072', _('128 Mbyte'))])
if os.path.isfile('/sbin/ntpd'):
    config.plugins.systemoptions.inettime = ConfigSelection(default='yes', choices=[('yes', _('yes')), ('no', _('no'))])
if os.path.isfile('/etc/init.d/sshd'):
    config.plugins.systemoptions.openssh = ConfigSelection(default='no', choices=[('yes', _('yes')), ('no', _('no'))])
if os.path.isfile('/usr/bin/inadyn'):
    config.plugins.systemoptions.inadyn = ConfigSelection(default='no', choices=[('yes', _('yes')), ('no', _('no'))])
if os.path.isfile('/lib/modules/cifs.ko'):
    config.plugins.systemoptions.cifs = ConfigSelection(default='no', choices=[('yes', _('yes')), ('no', _('no'))])
if os.path.isfile('/boot/audio_dts.elf'):
    config.plugins.systemoptions.dtsdownmix = ConfigSelection(default='on', choices=[('on', _('on')), ('off', _('off'))])
if stb.lower() == 'spark7162' or stb.lower() == 'spark':
    config.plugins.systemoptions.tunertype = ConfigSelection(default='t', choices=[('t', _('terrestrial (DVB-T)')), ('c', _('cable (DVB-C)'))])
config.plugins.systemoptions.extMenu = ConfigYesNo(default=True)
config.plugins.wireless = ConfigSubsection()
config.plugins.wireless.essid = ConfigText(default='your ssid', fixed_size=False)
config.plugins.wireless.encryption = ConfigSubsection()
config.plugins.wireless.encryption.type = ConfigSelection(default='no', choices=['no',
 'WEP',
 'WPA',
 'WPA2-AES',
 'WPA2-TKIP'])
config.plugins.wireless.encryption.wepkeyindex = ConfigSelection(default='1', choices=['1',
 '2',
 '3',
 '4'])
config.plugins.wireless.encryption.key = ConfigPassword(default='your pass phrase or key', fixed_size=False)
config.plugins.wireless.settings = ConfigSubsection()
config.plugins.wireless.settings.LinkMode = ConfigSelection(default='Infrastructure', choices=[('Infrastructure', _('infrastructure')), ('Adhoc', _('adhoc'))])
config.plugins.wireless.settings.WMode = ConfigSelection(default='11b/g/n-mixed', choices=[('A', _('11a-only')),
 ('ABG', _('11a/b/g-mixed')),
 ('ABGN', _('11a/b/g/n-mixed')),
 ('AGN', _('11a/g/n-mixed')),
 ('AN', _('11a/n-mixed')),
 ('B', _('11b-only')),
 ('BG', _('11b/g-mixed')),
 ('BGN', _('11b/g/n-mixed')),
 ('G', _('11g-only')),
 ('GN', _('11g/n-mixed')),
 ('N', _('11n-only'))])
config.plugins.wireless.settings.TxPower = ConfigSelection(default='100', choices=[('20', _('20%')),
 ('40', _('40%')),
 ('60', _('60%')),
 ('80', _('80%')),
 ('100', _('100%'))])
config.plugins.wireless.adapter = ConfigSubsection()
config.plugins.wireless.adapter.dhcp = ConfigYesNo(default=True)
config.plugins.wireless.adapter.ipaddress = ConfigIP(default=[192,
 168,
 178,
 100])
config.plugins.wireless.adapter.mask = ConfigIP(default=[255,
 255,
 255,
 0])
config.plugins.wireless.adapter.gateway = ConfigIP(default=[192,
 168,
 178,
 1])

class ConfigOptions(Screen, ConfigListScreen):
    skin = '\n\n\t<screen name="dummy" position="center,center" size="750,470" title="Setup">\n\t\t<eLabel text="System options configuration" position="85,30" size="1085,55" backgroundColor="secondBG" transparent="1" zPosition="1" font="Regular;24" valign="center" halign="left" />\n\t</screen>'

    def __init__(self, session):
        Screen.__init__(self, session)
        self.session = session
        self.restartbox = None
        self.skinName = ['Setup']
        self.setTitle(_('System options configuration'))
        self['key_red'] = self['red'] = Label(_('Cancel'))
        if stb.lower() == 'spark7162' or stb.lower() == 'spark':
            self['key_green'] = self['green'] = Label(_('OK'))
        else:
            self['key_green'] = self['green'] = Label(_('OK'))
        self['key_yellow'] = self['yellow'] = Label(_('Reboot receiver'))
        self.cfglist = []
        ConfigListScreen.__init__(self, self.cfglist)
        self.setTitle(_('System option configuration'))
        if stb.lower() == 'spark7162' or stb.lower() == 'spark':
            self['actions'] = ActionMap(['OkCancelActions',
             'DirectionActions',
             'InputActions',
             'ColorActions'], {'left': self.keyLeft,
             'down': self.keyDown,
             'up': self.keyUp,
             'right': self.keyRight,
             'cancel': self.cancel,
             'ok': self.keySave,
             'red': self.cancel,
             'green': self.keySaveSpark,
             'yellow': self.keyYellow}, -2)
        else:
            self['actions'] = ActionMap(['OkCancelActions',
             'DirectionActions',
             'InputActions',
             'ColorActions'], {'left': self.keyLeft,
             'down': self.keyDown,
             'up': self.keyUp,
             'right': self.keyRight,
             'cancel': self.cancel,
             'ok': self.keySave,
             'red': self.cancel,
             'green': self.keySave,
             'yellow': self.keyYellow}, -2)
        self.createSetup()
        return

    def createSetup(self):
        self.cfglist = []
        if stb.lower() == 'spark7162':
            self.cfglist.append(getConfigListEntry(_('Tuner C type:'), config.plugins.systemoptions.tunertype))
        if os.path.isfile('/boot/audio_dts.elf'):
            listadd = [getConfigListEntry(_('DTS downmix:'), config.plugins.systemoptions.dtsdownmix)]
            self.cfglist.extend(listadd)
        if os.path.isfile('/sbin/ntpd'):
            listadd = [getConfigListEntry(_('Synchronise with internet time:'), config.plugins.systemoptions.inettime)]
            self.cfglist.extend(listadd)
        self.cfglist.append(getConfigListEntry(_('Enable auto telnet login:'), config.plugins.systemoptions.autologin))
        self.cfglist.append(getConfigListEntry(_('Enable swap:'), config.plugins.systemoptions.swap))
        self.swap_enable = config.plugins.systemoptions.swap.value
        if self.swap_enable == 'yes':
            listadd = [getConfigListEntry(_('Swap size:'), config.plugins.systemoptions.swapsize)]
            self.cfglist.extend(listadd)
        if os.path.isfile('/etc/init.d/sshd'):
            listadd = [getConfigListEntry(_('Enable OpenSSH:'), config.plugins.systemoptions.openssh)]
            self.cfglist.extend(listadd)
        if os.path.isfile('/usr/bin/inadyn'):
            listadd = [getConfigListEntry(_('Enable inadyn:'), config.plugins.systemoptions.inadyn)]
            self.cfglist.extend(listadd)
        if os.path.isfile('/lib/modules/cifs.ko'):
            listadd = [getConfigListEntry(_('Enable CIFS:'), config.plugins.systemoptions.cifs)]
            self.cfglist.extend(listadd)
        self.cfglist.append(getConfigListEntry(_('WLAN driver:'), config.plugins.systemoptions.wlan))
        self.wlan_driver = config.plugins.systemoptions.wlan.value
        if self.wlan_driver != '0':
            listadd = [getConfigListEntry(_('  SSID:'), config.plugins.wireless.essid)]
            self.cfglist.extend(listadd)
            listadd = [getConfigListEntry(_('  Link mode:'), config.plugins.wireless.settings.LinkMode)]
            self.cfglist.extend(listadd)
            listadd = [getConfigListEntry(_('  Mode:'), config.plugins.wireless.settings.WMode)]
            self.cfglist.extend(listadd)
            listadd = [getConfigListEntry(_('  Transmitting power:'), config.plugins.wireless.settings.TxPower)]
            self.cfglist.extend(listadd)
            listadd = [getConfigListEntry(_('  Encryption:'), config.plugins.wireless.encryption.type)]
            self.cfglist.extend(listadd)
            self.wlan_encryption = config.plugins.wireless.encryption.type.value
            if self.wlan_encryption != 'no':
                if self.wlan_encryption == 'WPA2-AES':
                    listadd = [getConfigListEntry(_('    Pass phrase:'), config.plugins.wireless.encryption.key)]
                else:
                    listadd = [getConfigListEntry(_('    Encryption key:'), config.plugins.wireless.encryption.key)]
                self.cfglist.extend(listadd)
                if self.wlan_encryption == 'WEP':
                    listadd = [getConfigListEntry(_('    WEP key index:'), config.plugins.wireless.encryption.wepkeyindex)]
                    self.cfglist.extend(listadd)
            self.cfglist.append(getConfigListEntry(_('  DHCP:'), config.plugins.wireless.adapter.dhcp))
            self.wlan_dhcp = config.plugins.wireless.adapter.dhcp.value
            if self.wlan_dhcp == False:
                listadd = [getConfigListEntry(_('    IP address:'), config.plugins.wireless.adapter.ipaddress)]
                self.cfglist.extend(listadd)
                listadd = [getConfigListEntry(_('    Netmask:'), config.plugins.wireless.adapter.mask)]
                self.cfglist.extend(listadd)
                listadd = [getConfigListEntry(_('    Gateway IP address:'), config.plugins.wireless.adapter.gateway)]
                self.cfglist.extend(listadd)
        self.cfglist.append(getConfigListEntry(_('Show this plugin in plugin menu'), config.plugins.systemoptions.extMenu))
        self['config'].setList(self.cfglist)

    def cancel(self):
        ConfigListScreen.keyCancel(self)

    def keySave(self):
        ConfigListScreen.keySave(self)
        if config.plugins.systemoptions.swap.value == True:
            dummy = open('/tmp/setswap', 'a')
        self.close()

    def keySaveSpark(self):
        ConfigListScreen.keySave(self)
        if config.plugins.systemoptions.swap.value == True:
            dummy = open('/tmp/setswap', 'a')

    def keyYellow(self):
        self.restartbox = self.session.openWithCallback(self.restartE2, MessageBox, _('Do you really want to restart the receiver now?'), type=MessageBox.TYPE_YESNO, default=False)
        self.restartbox.setTitle(_('Reboot receiver'))

    def keyLeft(self):
        self['config'].handleKey(KEY_LEFT)
        self.createSetup()

    def keyRight(self):
        self['config'].handleKey(KEY_RIGHT)
        self.createSetup()

    def keyDown(self):
        self['config'].instance.moveSelection(self['config'].instance.moveDown)

    def keyUp(self):
        self['config'].instance.moveSelection(self['config'].instance.moveUp)

    def restartE2(self, answer):
        if answer is True:
            self.session.open(TryQuitMainloop, 2)
        else:
            self.close()


def opencfg(session, **kwargs):
    session.open(ConfigOptions)


def Optionsmenu(menuid, **kwargs):
    if menuid == 'expert':
        return [(_('System options'),
          opencfg,
          'systemoptions_setting',
          46)]
    else:
        return []


def Plugins(**kwargs):
    l = [PluginDescriptor(name=_('System options'), description=_('System options configuration'), where=PluginDescriptor.WHERE_MENU, fnc=Optionsmenu)]
    if config.plugins.systemoptions.extMenu.value:
        l.append(PluginDescriptor(name=_('System options'), description=_('System configuration options'), where=PluginDescriptor.WHERE_PLUGINMENU, fnc=opencfg))
    return l
