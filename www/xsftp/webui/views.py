#!/usr/bin/python
############################################################################
#
# Fcombine - An enterprise grade automounter and file server
# Copyright (C) 2013 George Murdocca
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#############################################################################

###################################
#            Imports
###################################

import django.core.mail
from django.http import HttpResponse, HttpResponseRedirect, Http404
from django.shortcuts import render_to_response
from django.contrib import auth
from django.template import RequestContext
from django.core.servers.basehttp import FileWrapper
import django
import xsftp
import xsftp.webui.forms
import xsftp.webui.models
import xsftp.webui.constants
from datetime import datetime
import time, random, os, decimal
from django.db.models import Q
import threading
import smtplib, socket
import subprocess
import operator
import stat
import pickle
from UserDict import UserDict
import new
import xsftp.common.constants
from xsftp.webui.logger import log
from xsftp.common.Licenses import Licenses


###################################
#           Constants
###################################

# Log levels
INFO = 0
WARNING = 1
CRITICAL = 2
DEBUG = 3
# breadcrumbs
MAX_BREADCRUMS = 50
# setup threading lock for editing KNOWN_HOSTS file
knownHostsFileLock = threading.Lock()
TRANSIENT_KEY_PATH = xsftp.webui.constants.TRANSIENT_KEY_PATH
# set the _fqdn value for the django.core.mail.CachedDnsName() instance called DNS_NAME in django.core.mail to this systems device name.
# This is to prevent django-generated emails appearing to come from an RFC 2606 reserved domain (namely localhost.localdomain) which upsets some SMTP servers.
django.core.mail.DNS_NAME._fqdn = xsftp.webui.models.Configuration.objects.all()[0].device_name
# grab the page title variable
TITLE = xsftp.webui.constants.PAGE_TITLE
LICENSE = Licenses()
# get clock ticks per second value for evaluating cpu utilisation
_CLOCK_TICKS = os.sysconf(os.sysconf_names["SC_CLK_TCK"])

###################################
#   Utilty Functions and Classes
###################################

def delKeyFingerPrint(server):
    '''
    Deletes the entry for the given server object in KNOWN_HOSTS file
    '''
    # Open the known hosts file for reading, and read its lines
    f = file(xsftp.common.constants.KNOWN_HOSTS_FILE, 'r')
    known_hosts = f.readlines()
    f.close()
    lines_to_keep = []
    # For line in known_hosts:
    for line in known_hosts:
        # if the address part of the line is not equal to server.address
        if not server.address in [hostname.split(":")[0].replace("[","").replace("]","") for hostname in line.split()[0].split(",")]:
            # Add the line to the list of lines that are OK
            lines_to_keep.append(line)
    # Open the known hosts file for writing, write lines, close.
    knownHostsFileLock.acquire()
    f = file(xsftp.common.constants.KNOWN_HOSTS_FILE, 'w')
    f.write("".join(lines_to_keep))
    f.close()
    knownHostsFileLock.release()

def setLinuxPassword(user, password):
    '''
    Sets an xsftp user's password in linux land. 'user' is a string representing the username of the xsftp user.
    '''
    # sanitise the password
    password = password.replace("'", r"'\''")
    pwdChCmd = "sudo %swww/xsftp/webui/privexec.py --password=%s,'%s'  > /dev/null 2>&1" % (xsftp.common.constants.APPDIR, user, password)
    os.system(pwdChCmd)

    
def render_response(template, request, params):
    params["messages"] = getMessages(request)
    return render_to_response(template, params, context_instance=RequestContext(request))


def putMessage(request, message, type=INFO, no_escape=False):
    if "messages" not in request.session.keys():
        request.session["messages"] = list()
    messages = request.session["messages"][:]
    messages.append((str(message), type, no_escape))
    request.session["messages"] = messages[:]


def getMessages(request, delete=True):
    '''
    Returns a list, each value being a tuple ('message', msgType, no_escape), or None
    '''
    if "messages" not in request.session.keys():
        return None
    if request.session["messages"]:
        messages = request.session["messages"][:]
        if delete == True:
            request.session["messages"] = list()
        return messages
    return None


def admin_required(theView):
    def wrapper(request, *args, **kwargs):
        if not request.user.is_staff:
            raise Http404
        return theView(request, *args, **kwargs)
    return wrapper


def valid_user(theView):
    def wrapper(request, *args, **kwargs):
        user = request.user
        if user.is_authenticated():
            if user.is_active:
                if not user.userprofile.is_expired():
                    return theView(request, *args, **kwargs)
                else: putMessage(request, "Sorry, your account has expired", CRITICAL)
            else:
                putMessage(request, "Sorry, your account is disabled", CRITICAL)
            return dologout(request)
        else:
            putMessage(request, "You need to login to view this page", WARNING)
        return HttpResponseRedirect("/accounts/login/?next=%s" % request.get_full_path())
    return wrapper

def is_demo_user(request):
    '''
        returns True if user is a demo user and demo_mode is enabled
    '''
    if xsftp.webui.models.Configuration.objects.all()[0].demo_mode and request.user.userprofile.is_demo_user:
        return True
    return False
    
def demo_user_block(request):
    '''
    Blocks a demo user and returns them to referring URL
    '''
    putMessage(request, "Sorry, you are unable to perform this function as a Demo user.", CRITICAL)
    return HttpResponseRedirect(request.META["HTTP_REFERER"])


def getUserByID(userid):
    '''
    Helper function which returns a User object based on an id
    '''
    return auth.models.User.objects.get(id = userid)


def getUserProfileByID(userid):    
    '''
    Helper function which returns a UserProfile object based on an id
    '''
    return xsftp.webui.models.UserProfile.objects.get(user=userid)


def getHomeURL(request):
    '''
    Helper function which returns home url based on user's role (admin or operator)
    '''
    if request.user.is_staff:
        return "/status/"
    else:
        return "/explorer/"


def confirm_action(request, action, objects, description, processor):
    params = {'title': '%s Confirm %s?' % (TITLE, action.title()),
            'action': action,
            'action_description':xsftp.webui.constants.BUTTON_DESCRIPTIONS[action],
            'objects': objects,
            'description': description,
            'processor': processor}
    return render_response("confirm_action.html", request, params)


def pushBreadCrumb(request, breadCrumb):
    if "breadCrumbs" not in request.session.keys():
        request.session["breadCrumbs"] = []
    bcid = random.randint(0, 100000)
    # make sure we don't double up our bcids
    while bcid in [bc[2] for bc in request.session["breadCrumbs"]]:
        bcid = random.randint(0, 100000)
    # prevent doubleups in breadcrumbs - sorry phil this is a major bandaid but i couldnt resist seeing the behaviour!
    if not request.session["breadCrumbs"] or (request.session["breadCrumbs"] and not request.session["breadCrumbs"][-1][1] == breadCrumb[1]):
        request.session["breadCrumbs"].append(breadCrumb + (bcid,))
    # make sure the breadcrumbs trail doesn't get too long
    if len(request.session["breadCrumbs"]) > MAX_BREADCRUMS:
        request.session["breadCrumbs"] = request.session["breadCrumbs"][-MAX_BREADCRUMS:]
    return

def popBreadCrumb(request):    
    if "breadCrumbs" not in request.session.keys():
        request.session["breadCrumbs"] = []
        return
    if request.session["breadCrumbs"]:
        request.session["breadCrumbs"].pop()
    return


def clearBreadCrumbs(request):
    # if the session breadcrumbs exists
    if "breadCrumbs" in request.session.keys():
        # remove all breadcrumbs from the session breadcrumbs
        request.session["breadCrumbs"] = list()


def uptime(seconds_only=False):
    '''
    Reads uptime info from /proc/uptime and returns it as a nicely formatted string.
    If seconds_only = True, number of seconds uptime is returned as an int.
    '''
    try:
        f = open( "/proc/uptime" )
        contents = f.read().split()
        f.close()
    except:
        return "Cannot open uptime file: /proc/uptime"
    total_seconds = float(contents[0])
    if seconds_only:
        return int(total_seconds)
    # Helper vars:
    MINUTE  = 60
    HOUR    = MINUTE * 60
    DAY     = HOUR * 24
    # Get the days, hours, etc:
    days    = int( total_seconds / DAY )
    hours   = int( ( total_seconds % DAY ) / HOUR )
    minutes = int( ( total_seconds % HOUR ) / MINUTE )
    seconds = int( total_seconds % MINUTE )
    # Build up the pretty string (like this: "N days, N hours, N minutes, N seconds")
    string = ""
    if days> 0:
        string += str(days) + " " + (days == 1 and "day" or "days" ) + ", "
    if len(string)> 0 or hours> 0:
        string += str(hours) + " " + (hours == 1 and "hour" or "hours" ) + ", "
    if len(string)> 0 or minutes> 0:
        string += str(minutes) + " " + (minutes == 1 and "minute" or "minutes" ) + ", "
    string += str(seconds) + " " + (seconds == 1 and "second" or "seconds" )
    return string;


def nullbool_to_string(value):
    '''
    returns 'Yes' if value is True, 'No' if value is False, and 'N/A' if value is something else
    '''
    if value:
        return 'Yes'
    elif value == False:
        return 'No'
    else:
        return 'N/A'

def is_daemon_running():
    rc = os.system("/etc/init.d/xsftpd status > /dev/null 2>&1")
    if rc == 0:
        return True
    return False


class odict(UserDict):
    '''
    An ordered dictionary
    '''
    def __init__(self, dict = None):
        self._keys = []
        UserDict.__init__(self, dict)
    def __delitem__(self, key):
        UserDict.__delitem__(self, key)
        self._keys.remove(key)
    def __setitem__(self, key, item):
        UserDict.__setitem__(self, key, item)
        if key not in self._keys: self._keys.append(key)
    def clear(self):
        UserDict.clear(self)
        self._keys = []
    def copy(self):
        dict = UserDict.copy(self)
        dict._keys = self._keys[:]
        return dict
    def items(self):
        return zip(self._keys, self.values())
    def keys(self):
        return self._keys
    def popitem(self):
        try:
            key = self._keys[-1]
        except IndexError:
            raise KeyError('dictionary is empty')
        val = self[key]
        del self[key]
        return (key, val)
    def setdefault(self, key, failobj = None):
        UserDict.setdefault(self, key, failobj)
        if key not in self._keys: self._keys.append(key)
    def update(self, dict):
        UserDict.update(self, dict)
        for key in dict.keys():
            if key not in self._keys: self._keys.append(key)
    def values(self):
        return map(self.get, self._keys)


def clean_session(request):
    request.session["clipboard_items"] = list()


###################################################
#         Login / Auth-not-required views
###################################################


def root(request):
    return HttpResponseRedirect("/login/")


def login(request):
    # if the user is already logged in
    if request.user.is_authenticated():
        # redirect them to their homepage
        return HttpResponseRedirect(getHomeURL(request))
    login_form = xsftp.webui.forms.LoginForm()
    request.session.set_test_cookie()
    err_message = []
    if request.GET.has_key("cookie_error") and request.GET["cookie_error"] == "True":
        err_message = [("It appears your browser is not configured to accept cookies, or that your previous session has expired. Please check that cookies are enabled, and/or try again.", WARNING)]
    messages = err_message + (getMessages(request) or [])
    params = {
        'title':"%s Login" % TITLE,
        'messages': messages,
        'login_form':login_form,
        'current_date': time.strftime("%a, %m %B %Y"),
        'current_year':time.strftime("%Y"),
        'xsftp_version':xsftp.webui.constants.FCOMBINE_VERSION,
        'license': LICENSE,
        'device_name':xsftp.webui.models.Configuration.objects.all()[0].get_device_name(),
        }
    return render_to_response('login.html', params)


def dologin(request):
    # if they just tried to GET dologin
    if request.method == "GET" or "username" not in request.POST.keys() or "password" not in request.POST.keys():
        return HttpResponseRedirect("/")
    # Else, they sent a post
    # check if the test cookie was ok, if not, throw message saying cookies are required
    if not request.session.test_cookie_worked():
        log("rejected login attempt due to lack of cookie support in client browser")
        return HttpResponseRedirect("/login/?cookie_error=True")
    request.session.delete_test_cookie()
    u = request.POST["username"]
    p = request.POST["password"]
    user = auth.authenticate(username = u, password = p)
    # If they failed to authenticate
    if not user:
        putMessage(request, "Login failed. Please note that both fields are case sensitive.", WARNING)
        log("rejected invalid login attempt for user specified as: %s" % u)
        return HttpResponseRedirect("/login/")
    # Else, check if they are active.. if so log them in
    if user.is_active:
        if not user.userprofile.is_expired():
            auth.login(request, user)
            # modify the user's last_login value:
            user.last_login = time.strftime("%Y-%m-%d %H:%M:%S")
            putMessage(request, "You have successfully logged in as %s" % (request.user.get_full_name() or request.user.username), INFO)
            log("user '%s' successfully logged in" % user.username)
            clean_session(request)
        else:
            putMessage(request, "Sorry, your account has expired.", WARNING)
            log("rejected login attempt for expired user account: %s" % user.username)
            return HttpResponseRedirect("/login/")
    else:
        # user is not active, tell them so
        putMessage(request, "Sorry, your account has been disabled.", WARNING)
        log("rejected login attempt for disabled user account: %s" % user.username)
        return HttpResponseRedirect("/login/")
    if "nexturl" in request.session.keys():
        nexturl = request.session["nexturl"]
        del request.session["nexturl"]
    else:
        # they are active, everything checks out, send them to their homepage
        nexturl = getHomeURL(request)
    return HttpResponseRedirect(nexturl)


def accountsLogin(request):
    '''This view is purely to work around the fact that we can't change the default LOGIN_URL in this version of django'''
    request.session["nexturl"] = request.GET["next"]
    return HttpResponseRedirect("/login/")


def dologout(request):
    username = request.user.username
    auth.logout(request)
    putMessage(request, "You have been logged out.", INFO)
    log("logged out user account: %s" % username)
    return HttpResponseRedirect("/login/")


def help(request):
    # TODO put a webserver and page at this link or something :) 
    return HttpResponseRedirect("http://www.fcombine.com/fcombine/help")


###################################################
#             Admin Only Required Views
###################################################


# **************************************
#         Login & Toolbar Views
# **************************************


@valid_user
@admin_required
def status(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("Status", "/status/"))
    systemTime = time.ctime()
    # get load average in last 5 mins (ie. index 1 of getloadavg()) and round to two decimal palces
    loadAvg = [str(decimal.Decimal(str(la)).quantize(decimal.Decimal('0.01'))) for la in os.getloadavg()]
    # get cpu utilisation
    f = open('/proc/stat', 'r')
    idle_jiffies = float(f.readline().split()[4])
    f.close()
    seconds_idle_since_boot = idle_jiffies / _CLOCK_TICKS
    cpuUtilisation = 100 - seconds_idle_since_boot * 100 / uptime(seconds_only=True)
    cpuUtilisation = round(cpuUtilisation, 2)
    #cpuUtilisation = values
    # get mem utilisation
    f = open('/proc/meminfo', 'r')
    mem_lines = [line.strip() for line in f.readlines()]
    f.close()
    for line in mem_lines:
        if line.startswith('MemTotal:'):
            mem_total = int(line.split()[1])
        if line.startswith('MemFree:'):
            mem_free = int(line.split()[1])
        if line.startswith('Buffers:'):
            mem_buffers = int(line.split()[1])
        if line.startswith('Cached:'):
            mem_cached = int(line.split()[1])
    mem_available = (mem_free + mem_buffers + mem_cached) * 100 / mem_total # as a percentage
    # get cpu count
    try:
        cpuCount = os.sysconf("SC_NPROCESSORS_ONLN")
    except ValueError:
        # fallback: parse /proc/cpuinfo
        cpuCount = 0
        f = open('/proc/cpuinfo', 'r')
        try:
            lines = f.readlines()
            for line in lines:
                if line.lower().startswith('processor'):
                    cpuCount += 1
        except:
            cpuCount = "Unknown"
        f.close()
    # getcurrently logged in webui users by:
    #   1. getting all sessions
    allSessions = [s.get_decoded() for s in django.contrib.sessions.models.Session.objects.all()]
    #   2. getting authentication related sessions
    authSessions = [d1['_auth_user_id'] for d1 in allSessions if d1.has_key("_auth_user_id")]
    #   3 .uniquifying
    uAuthSessions = [d2.setdefault(x,x) for d2 in [{}] for x in authSessions if x not in d2]
    #   4. converting to user object list
    webuiUsers = [xsftp.webui.models.User.objects.get(id=u) for u in uAuthSessions]
    # get ethernet information:
    p = subprocess.Popen(["sudo %swww/xsftp/webui/privexec.py --ethinfo" % xsftp.common.constants.APPDIR], shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE, close_fds=True)
    (pout, pin) = (p.stdout, p.stdin)
    ethData = pout.read().strip()
    if ethData:
        ethinfo = [(item.split(":")[0], item.split(":")[1]) for item in  ethData.split(";")]
    else:
        ethinfo = []
    # exclude unnecessary ethernet info (iw. info returned by ethtool)
    filteredEthinfo = []
    for item in ethinfo:
        if item[0] not in [ "Current message level",
                            "Supported ports",
                            "PHYAD",
                            "Transceiver",
                            "Supports Wake-on",
                            "Wake-on",
                            "Supported link modes",
                            "Supports auto-negotiation",
                            "Advertised pause frame use",
                            "MDI-X",
                            "Port",
                            "Link detected"
                          ]:
            filteredEthinfo.append(item)
    if not filteredEthinfo:
        filteredEthinfo = [('Unknown','Network information is unavailable')]
    params ={'title':'%s Status' % TITLE,
        'pageid':'status',
        'daemonStatus': is_daemon_running(),
        'systemTime': systemTime,
        'cpuUtilisation': cpuUtilisation,
        'memTotal': mem_total,
        'memAvailable': mem_available,
        'cpuCount': cpuCount,
        'loadAvg': loadAvg,
        'webuiUsers': webuiUsers,
        'webuiUserCount': len(webuiUsers),
        'uptime': uptime(),
        'ethinfo': filteredEthinfo,
        'config': xsftp.webui.models.Configuration.objects.all()[0],
        }
    return render_response('status.html', request, params)

@valid_user
@admin_required
def servicestart(request):
    '''
    Starts the xSFTP service
    '''
    os.system('sudo %swww/xsftp/webui/privexec.py --start > /dev/null 2>&1' % xsftp.common.constants.APPDIR)
    putMessage(request, "Fcombine Service Started.", INFO)
    log("User '%s' has STARTED the Fcombine Service" % request.user)
    return HttpResponseRedirect('/status/')


@valid_user
@admin_required
def servicestop(request):
    '''
    Stops the xSFTP service
    '''
    if is_demo_user(request): return demo_user_block(request)
    os.system('sudo %swww/xsftp/webui/privexec.py --stop > /dev/null 2>&1' % xsftp.common.constants.APPDIR)
    putMessage(request, "Fcombine Service Stopped.", INFO)
    log("User '%s' has STOPPED the Fcombine Service" % request.user)
    return HttpResponseRedirect('/status/')


# **************************************
#            User Views
# **************************************


@valid_user
@admin_required
def users(request):
    # This is root level view, so reset the breadCrumbs
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("Users", "/users/"))
    # Using leet tables
    # If the the following submit values are in the GET paramaters, then handle them
    request.session["use_existing_bcid"] = True
    if "button" in request.GET.keys():
        # They clicked filter, disable, enable or delete
        if request.GET["button"] in ("Delete", "Disable", "Enable"):
            if request.GET.getlist("selected"):
                # call the confirmation view - give it the verb, the nouns, and a description of the nouns
                return confirm_action(request, action=request.GET["button"], objects=[xsftp.webui.models.User.objects.get(id=uid) for uid in request.GET.getlist("selected")], description="User", processor="/users/")
            else:
                putMessage(request, "You didn't select any Users to %s" % request.GET["button"].lower(), WARNING)
    headings = []
    LeetHeading = xsftp.webui.forms.LeetHeading # could import it specifically, but this should work too
    headings.append((LeetHeading("_select_all", render_as="checkbox", sortable=False), "id"))
    headings.append((LeetHeading("Username", render_as="link"), "username"))
    headings.append((LeetHeading("First Name"), "first_name"))
    headings.append((LeetHeading("Last Name"), "last_name"))
    # if the requestor is the built-in admin and demo mode is on:
    if xsftp.webui.models.Configuration.objects.all()[0].demo_mode and request.user.id == 1:
        # show the is_demo_user status
        headings.append((LeetHeading("Demo User", render_as="text_boolean"), "userprofile__is_demo_user"))
    headings.append((LeetHeading("Local", render_as="text_boolean"), "userprofile__internal_auth"))
    headings.append((LeetHeading("Email"), "email"))
    headings.append((LeetHeading("Groups", render_as="multi_link", sortable=False), "xgroup__group_name"))
    headings.append((LeetHeading("Enabled", render_as="boolean"), "is_active"))
    headings.append((LeetHeading("Expired"), "userprofile__expiry"))
    headings.append((LeetHeading("Admin", render_as="boolean"), "is_staff"))
    headings.append((LeetHeading("Comment"), "userprofile__comment"))
    # Build the query object
    filter = ""
    if "filter" in request.GET.keys():
        filter = request.GET["filter"]
        q_object =     Q(username__icontains=filter) |\
                    Q(first_name__icontains=filter) |\
                       Q(last_name__icontains=filter) |\
                    Q(email__icontains=filter) |\
                    Q(userprofile__comment__icontains=filter) |\
                    Q(xgroup__group_name__icontains=filter)
        users = auth.models.User.objects.filter(q_object) # might be worth adding in a "select_related", given that we know we will need the xGroup and userprofile objects later
    else:
        users = auth.models.User.objects.all()
    # Now sort the users based on the appropriate column
    # First, set sortOrder and sortCol to sensible defaults
    sortOrder = "asc"
    sortCol = "username"
    # Then overwrite them if they have been specified
    if "sortCol" in request.GET.keys():
        passed_sortCol = request.GET["sortCol"]
        if passed_sortCol in [h[1] for h in headings]:
            sortCol = passed_sortCol
    if "sortOrder" in request.GET.keys():
        sortOrder = request.GET["sortOrder"]
    if sortOrder == "desc":
        sortCol = "-%s" % sortCol
    # Now actually sort the users ...
    users = users.order_by(sortCol)
    # Now build a list of the user attribute tuples to put in the leet table
    userList = odict()
    for user in users:
        if unicode(user.id) in request.GET.getlist("selected"):
            selected = 1
        else:
            selected = 0
        if xsftp.webui.models.Configuration.objects.all()[0].demo_mode and request.user.id == 1:
            userList[user.id] = ((user.id, selected), (user.username, "/users/view/%s/" % user.id), user.first_name, user.last_name, user.userprofile.is_demo_user, user.userprofile.internal_auth, user.email, [(g.group_name, "/groups/view/%s/" % g.id) for g in user.xgroup_set.all()], user.is_active, nullbool_to_string(user.userprofile.is_expired()), user.is_staff, user.userprofile.comment)
        else:
            userList[user.id] = ((user.id, selected), (user.username, "/users/view/%s/" % user.id), user.first_name, user.last_name, user.userprofile.internal_auth, user.email, [(g.group_name, "/groups/view/%s/" % g.id) for g in user.xgroup_set.all()], user.is_active, nullbool_to_string(user.userprofile.is_expired()), user.is_staff, user.userprofile.comment)
    button_list = []
    button_list.append(xsftp.webui.forms.LeetButton(value="Enable"))
    button_list.append(xsftp.webui.forms.LeetButton(value="Disable"))
    button_list.append(xsftp.webui.forms.LeetButton(value="Delete"))
    totalUsers = auth.models.User.objects.count()
    the_table = xsftp.webui.forms.LeetTable(action="/users/", headings=headings, objects=userList.values(), filterable=True, sortable=True, buttons=button_list, filter=filter, totalObjects=totalUsers, sortCol=sortCol, sortOrder=sortOrder, objectDescription="User")
    params = {'title':'%s Users' % TITLE,
        'pageid':'users',
        'leet_table':the_table,
        }
    return render_response('users.html', request, params)


@valid_user
@admin_required
def domodifyusers(request, action):
    if request.POST["button"] != "Yes":
        putMessage(request, "%s cancelled" % action.title(), WARNING)
        return HttpResponseRedirect("/users/")
    # ensure the built-in admin account is never changed
    if "1" in request.POST.getlist("selected"):
        putMessage(request, "The built-in administrator account can not be disabled or deleted.", CRITICAL)
        return HttpResponseRedirect("/users/")
    if request.user.id in request.POST.getlist("selected"):
        putMessage(request, "You can not disable or delete your own account.", CRITICAL)
        return HttpResponseRedirect("/users/")    
    if is_demo_user(request): return demo_user_block(request)
    if action == "delete":
        users_to_delete = [xsftp.webui.models.User.objects.get(id=userid) for userid in request.POST.getlist("selected")]
        usernames_to_delete = [userObj.username for userObj in users_to_delete]
        # for each selected user
        inherited_jobs = []
        for user in users_to_delete:
            # Reassign any jobs owned by these users-to-be-deleted to the current administrator doing the deletion
            for job in user.job_set.all():
                job.owner = request.user
                # force the job to be disabled.
                job.enabled = False
                job.save()
                inherited_jobs.append(job.job_name)
            # delete the user profile
            user.userprofile.delete()
            # Delete the user
            user.delete()
            # we have to manually call dbCommit, because we haven't subclassed the User objects, and thus can't modify the delete method to automatically call dbCommit()
            xsftp.webui.models.dbCommit()
        # Remove them from the radius file if they are in there
        f = file(xsftp.webui.constants.PAM_RADIUS_USERS, 'r+')
        lines = f.readlines()
        f.seek(0)
        for line in lines:
            if str(line.strip()) not in str(usernames_to_delete):
                f.write(line)
        f.truncate()
        f.close()
        putMessage(request, "Selection(s) deleted.", INFO)
        if inherited_jobs:
            inherited_message = "You have inherited %s orhpaned job(s): %s" % (len(inherited_jobs), "'" + "', '".join(inherited_jobs) + "'")
            putMessage(request, inherited_message, WARNING)
        log("user '%s' has deleted user accounts: %s and has inherited job(s):%s" % (request.user.username, "'" + "' ,'".join(usernames_to_delete) + "'", "'" + "', '".join(inherited_jobs) + "'"))
    elif action == "disable":
        # disable the user, and save
        users_to_disable = [xsftp.webui.models.User.objects.get(id=user) for user in request.POST.getlist("selected")]
        for user in users_to_disable:
            user.is_active = False
            user.save()
        putMessage(request, "Selection(s) disabled", INFO)
        log("user '%s' has disabled user accounts: %s" % (request.user.username, "'" + "' ,'".join([user.username for user in users_to_disable]) + "'"))
    elif action == "enable":
        # enable the users and save
        users_to_enable = [xsftp.webui.models.User.objects.get(id=user) for user in  request.POST.getlist("selected")]
        for user in users_to_enable:
            user.is_active = True
            user.save()
        putMessage(request, "Selection(s) enabled", INFO)
        log("user '%s' has enabled user accounts: %s" % (request.user.username, "'" + "' ,'".join([user.username for user in users_to_enable]) + "'"))
    else:
        putMessage(request, "Unknown action provided - no action was taken", WARNING)
    return  HttpResponseRedirect("/users/")


@valid_user
@admin_required
def viewuser(request, userid):
    user = auth.models.User.objects.get(id = userid)
    last_login = user.last_login.replace(microsecond=0)
    users_groups = user.xgroup_set.all()
    users_scripts = user.userprofile.getEffectiveScripts()
    users_read_servers = user.userprofile.getEffectiveReadServers()
    users_write_servers = user.userprofile.getEffectiveWriteServers()
    if request.user.id == 1 and xsftp.webui.models.Configuration.objects.all()[0].demo_mode and user.id != 1:
        show_demo_status = True
    else:
        show_demo_status = False
    pushBreadCrumb(request, ("View User '%s'" % user.username, "/users/view/%s/" % userid))
    params = {'title':'%s User Details' % TITLE,
        'pageid':'users',
        'last_login':last_login,
        'user_to_view':user,
        'users_groups':users_groups,
        'users_scripts':users_scripts,
        'users_read_servers':users_read_servers,
        'users_write_servers':users_write_servers,
        'user_profile_to_view':user.userprofile,
        'show_demo_status':show_demo_status,
        }
    return render_response('viewuser.html', request, params)


@valid_user
@admin_required
def adduser(request):
    pushBreadCrumb(request, ("Add User", "/users/add/"))
    newuserform = xsftp.webui.forms.NewUserForm()
    if request.method == 'POST':
        if is_demo_user(request): return demo_user_block(request)
        newuserform = xsftp.webui.forms.NewUserForm(request.POST)
        if newuserform.is_valid():
            newuserform.save()
            # set users password in linux
            if newuserform.cleaned_data['internal_auth']:
                setLinuxPassword(newuserform.cleaned_data['username'], newuserform.cleaned_data['password_1'])
            else:
                # Add them to the radius list
                f = file(xsftp.webui.constants.PAM_RADIUS_USERS, 'a')
                f.write("%s\n" % newuserform.cleaned_data['username'])
                f.close()
            putMessage(request, "Successfully created new user: %s" % request.POST["username"], INFO)
            newuserform = xsftp.webui.forms.NewUserForm()
            log("user '%s' has created new user account: %s" % (request.user.username, request.POST["username"]))
        else:
            putMessage(request, "Please correct the errors below.", CRITICAL)
            # we need to clear the password, but we are not allowed to modify the immutable QueryDict named Data
            # Instaed, we make a copy, and then re-attach the copy to the form in place of the original
            newData = newuserform.data.copy()
            newData["password_1"] = u''
            newData["password_2"] = u''
            newuserform.data = newData
    # restrict user addition based on number of allowed licenses
    max_allowed_users = LICENSE.get_active_license_count('USER')
    if len(xsftp.webui.models.Server.objects.all()) >= max_allowed_users:
        putMessage(request, "You have reached your subscription limit of %s Users. Click <a href=/subscriptions/>here</a> to see your subscriptions." % max_allowed_users, CRITICAL, no_escape=True)
        return HttpResponseRedirect('/users/')
    params = {'title':'%s Add New User' % TITLE,
        'pageid':'users',
        'newuserform':newuserform,
        }
    return render_response("adduser.html", request, params)


@valid_user
@admin_required
def edituser(request, userid):
    # set a flag if this is the admin user so we know not to present some fields like expiry
    if userid == "1":
        is_administrator = True
    else:
        is_administrator = False
    # get user object specified by userid arg
    user = auth.models.User.objects.get(id = userid)    
    # get status of internal_auth
    current_internal_auth = user.userprofile.internal_auth
    pushBreadCrumb(request, ("Edit User '%s'" % user.username, "/users/edit/%s/" % userid))
    # check if they just came to this form via clicking "Edit User", or are actually submitting some modifications
    all_user_attributes = request.POST.copy()
    if request.POST:
        # they are submitting some modifications, validate them.
        # if "Cancel" button was pressed
        if request.POST["button"] == "Cancel":
            # return to previous page
            popBreadCrumb(request)
            putMessage(request, "Cancelled user modification", WARNING)
            return HttpResponseRedirect("/users/view/%s/" % userid)
        # populate and validate the form
        if is_demo_user(request): return demo_user_block(request)
        edit_user_form = xsftp.webui.forms.EditUserForm(is_administrator, request.user, request.POST)
        if edit_user_form.is_valid():
            edit_user_form.save()
            popBreadCrumb(request)
            putMessage(request, "Successfully modified user: '%s'" % user, INFO)
            # if the auth has changed from internal to external or vice versa
            if not current_internal_auth == edit_user_form.cleaned_data.get('internal_auth'):
                # if the auth has changed from NOT internal to internal, warn admin that the user's local password needs to be re-created
                if edit_user_form.cleaned_data.get('internal_auth'):
                    putMessage(request, "The password for this user needs to be set." % user, WARNING)
                    # Remove them from the radius users file
                    # XXX Wrap the following file access in try/except
                    f = file(xsftp.webui.constants.PAM_RADIUS_USERS, 'r+')
                    lines = f.readlines()
                    f.seek(0)
                    for line in lines:
                        if not str(line.strip()) == str(edit_user_form.cleaned_data['username']):
                            f.write(line)
                    f.truncate()
                    f.close()
                else:
                    # Add them to the radius users file
                    f = file(xsftp.webui.constants.PAM_RADIUS_USERS, 'a')
                    f.write("%s\n" % edit_user_form.cleaned_data['username'])
                    f.close()
            log("user '%s' has modified user account: %s" % (request.user.username, user))
            return HttpResponseRedirect("/users/view/%s/" % userid)
        else:
            # form was invalid
            putMessage(request, "Please correct the errors below.", CRITICAL)
    else:
        # they got here by clicking "Edit User" on the user details page
        # get attributes of a user and their profile to populate the edit form's fields
        user_attributes = user.__dict__
        userprofile_attributes = user.userprofile.__dict__
        # combine the two attribute dicts
        all_user_attributes = user_attributes.copy()
        all_user_attributes.update(userprofile_attributes)
        # add the user_id bit (hidden field)
        all_user_attributes['user_id'] = userid
    # instantiate the form
    edit_user_form = xsftp.webui.forms.EditUserForm(is_administrator, request.user, all_user_attributes)
    params = {"title":'%s Edit User' % TITLE,
        'pageid':'users',
        'user_to_edit':user,
        "edit_user_form":edit_user_form,
        }
    return render_response("edituser.html", request, params)


@valid_user
@admin_required
def changeuserpass(request, userid):
    if not auth.models.User.objects.get(id=userid).userprofile.internal_auth:
        putMessage(request, "Passwords for non-local users can only be changed via your external user management system.", CRITICAL)
        return HttpResponseRedirect(request.META["HTTP_REFERER"])
    pushBreadCrumb(request, ("Change Password", "/users/changepassword/%s" % userid))
    if request.method == "POST":
        if request.POST["button"] != "Apply":
            popBreadCrumb(request)
            putMessage(request, "Cancelled password change", WARNING)
            return HttpResponseRedirect("/users/view/%s/" % userid)
        if is_demo_user(request): return demo_user_block(request)
        changeuserpassform = xsftp.webui.forms.ChangeUserPasswordForm(request.user, request.POST)
        if not changeuserpassform.is_valid():
            putMessage(request, "Please correct the errors below." , CRITICAL)
            # we need to clear the password, but we are not allowed to modify the immutable QueryDict named Data
            # Instaed, we make a copy, and then re-attach the copy to the form in place of the original
            newData = changeuserpassform.data.copy()
            newData["new_password_1"] = u''
            newData["new_password_2"] = u''
            changeuserpassform.data = newData
        else:
            user_to_change = auth.models.User.objects.get(id=userid)
            user_to_change.set_password(request.POST["new_password_1"])
            user_to_change.save()
            # set users password in linux
            setLinuxPassword(user_to_change.username, changeuserpassform.cleaned_data["new_password_1"])
            popBreadCrumb(request)
            putMessage(request, "Password for %s was changed successfully!" % (user_to_change.get_full_name() or user_to_change.username), INFO)
            log("user '%s' has changed the password user account: %s" % (request.user.username, user_to_change.username))
            return HttpResponseRedirect("/users/view/%s/" % userid)
    else:
        changeuserpassform = xsftp.webui.forms.ChangeUserPasswordForm(request.user)
    params = {'title':'%s Change User Password' % TITLE,
        'pageid':'changeuserpass',
        'myform':changeuserpassform,
        'user_to_change':auth.models.User.objects.get(id=userid),
        }
    return render_response('changeuserpass.html', request, params)


# **************************************
#            Group Views
# **************************************

@valid_user
@admin_required
def groups(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("Groups", "/groups/"))
    # Using leet tables
    # If the the following submit values are in the GET paramaters, then handle them
    if "button" in request.GET.keys():
        # They clicked filter, disable, enable or delete
        if request.GET["button"] in ("Delete"):
            if request.GET.getlist("selected"):
                # call the confirmation view - give it the verb, the nouns, and a description of the nouns
                return confirm_action(request, action=request.GET["button"], objects=[xsftp.webui.models.xGroup.objects.get(id=gid) for gid in request.GET.getlist("selected")], description="Group", processor="/groups/")
            else:
                putMessage(request, "You didn't select any Groups to %s" % request.GET["button"].lower(), WARNING)
    headings = []
    LeetHeading = xsftp.webui.forms.LeetHeading # could import it specifically, but this should work too
    headings.append((LeetHeading("_select_all", render_as="checkbox", sortable=False), "id"))
    headings.append((LeetHeading("Group Name", render_as="link"), "group_name"))
    headings.append((LeetHeading("Alertable", render_as="boolean"), "alertable"))
    headings.append((LeetHeading("Created"), "created"))
    headings.append((LeetHeading("Comment"), "comment"))
    # Build the query object
    filter = ""
    if "filter" in request.GET.keys():
        filter = request.GET["filter"]
        q_object =    Q(group_name__icontains=filter) |\
                    Q(created__icontains=filter) |\
                    Q(comment__icontains=filter)
        groups = xsftp.webui.models.xGroup.objects.filter(q_object)
    else:
        groups = xsftp.webui.models.xGroup.objects.all()
    # Now sort the users based on the appropriate column
    # First, set sortOrder and sortCol to sensible defaults
    sortOrder = "asc"
    sortCol = "group_name"
    # Then overwrite them if they have been specified
    if "sortCol" in request.GET.keys():
        passed_sortCol = request.GET["sortCol"]
        if passed_sortCol in [h[1] for h in headings]:
            sortCol = passed_sortCol
    if "sortOrder" in request.GET.keys():
        sortOrder = request.GET["sortOrder"]
    if sortOrder == "desc":
        sortCol = "-%s" % sortCol
    # Now actually sort the groups
    groups = groups.order_by(sortCol)
    # Now build a list of the group attribute tuples to put in the leet table
    groupList = odict()
    for group in groups:
        if unicode(group.id) in request.GET.getlist("selected"):
            selected = 1
        else:
            selected = 0
        groupList[group.id] = ((group.id, selected), (group.group_name, "/groups/view/%s/" % group.id), group.alertable, group.created, group.comment)
    button_list = []
    button_list.append(xsftp.webui.forms.LeetButton(value="Delete"))
    totalGroups = xsftp.webui.models.xGroup.objects.count()
    the_table = xsftp.webui.forms.LeetTable(action="/groups/", headings=headings, objects=groupList.values(), filterable=True, sortable=True, filter=filter, totalObjects=totalGroups, sortCol=sortCol, sortOrder=sortOrder, buttons=button_list, objectDescription="Group")
    params = {'title':'%s Groups' % TITLE,
        'pageid':'groups',
        'leet_table':the_table,
        }
    return render_response('groups.html', request, params)


@valid_user
@admin_required
def viewgroup(request, groupid):
    group = xsftp.webui.models.xGroup.objects.get(id = groupid)
    pushBreadCrumb(request, ("View Group '%s'" % group.group_name, "/groups/view/%s/" % groupid))
    users_in_group = group.users.all()
    params = {'title':'%s View Group' % TITLE,
        'pageid':'groups',
        'group_to_view':group,
        'users_in_group':users_in_group,
        }
    return render_response('viewgroup.html', request, params)


@valid_user
@admin_required
def editgroup(request, groupid):
    # get group object specified in userid arg
    group = xsftp.webui.models.xGroup.objects.get(id = groupid)
    pushBreadCrumb(request, ("Edit Group '%s'" % group.group_name, "/groups/edit/%s/" % groupid))
    # check if they just came to this form via clicking "Edit Group", or are actually submitting some modifications
    if request.POST:
        # they are submitting some modifications, validate them.
        # if "Cancel" button was pressed
        if request.POST["button"] == "Cancel":
            # return to previous page
            popBreadCrumb(request)
            putMessage(request, "Canceled group modification", WARNING)
            return HttpResponseRedirect("/groups/view/%s/" % groupid)
        # populate and validate the form
        if is_demo_user(request): return demo_user_block(request)
        edit_group_form = xsftp.webui.forms.EditGroupForm(request.POST)
        if edit_group_form.is_valid():
            edit_group_form.save()
            popBreadCrumb(request)
            putMessage(request, "Successfully modified group: '%s'" % group, INFO)
            log("user '%s' has modified user account: %s" % (request.user.username, group))
            return HttpResponseRedirect("/groups/view/%s/" % groupid)
        else:
            # form was invalid
            putMessage(request, "Please correct the errors below.", CRITICAL)
    else:
        edit_group_form = xsftp.webui.forms.EditGroupForm(group)
    # now render it
    params = {"title":'%s Edit Group' % TITLE,
        'pageid':'groups',
        'group_to_edit':group,
        'edit_group_form':edit_group_form,
        }
    return render_response("editgroup.html", request, params)


@valid_user
@admin_required
def addgroup(request):
    pushBreadCrumb(request, ("Add Group", "/groups/add/"))
    newgroupform = xsftp.webui.forms.NewGroupForm()
    if request.method == 'POST':
        if is_demo_user(request): return demo_user_block(request)
        newgroupform = xsftp.webui.forms.NewGroupForm(request.POST)
        if newgroupform.is_valid():
            newgroupform.save()
            putMessage(request, "Successfully created new group: %s" % request.POST["group_name"], INFO)
            newgroupform = xsftp.webui.forms.NewGroupForm()
            log("user '%s' has created new group: %s" % (request.user.username, request.POST["group_name"]))
        else:
            putMessage(request, "Please correct the errors below.", CRITICAL)
    params = {'title':'%s Add New Group' % TITLE,
        'pageid':'groups',
        'newgroupform':newgroupform,
        }
    return render_response("addgroup.html", request, params)


@valid_user
@admin_required
def domodifygroups(request, action):
    if request.POST["button"] != "Yes":
        putMessage(request, "%s cancelled" % action.title(), WARNING)
        return HttpResponseRedirect("/groups/")
    if is_demo_user(request): return demo_user_block(request)
    if action == "delete":
        # for each selected group
        groups_to_delete = [xsftp.webui.models.xGroup.objects.get(id=group) for group in request.POST.getlist("selected")]
        for group in groups_to_delete:
            # Delete the group
            group.delete()
        putMessage(request, "Selection(s) deleted", INFO)
        log("user '%s' has deleted groups: %s" % (request.user.username, "'" + "' ,'".join([group.group_name for group in groups_to_delete]) + "'"))
    else:
        putMessage(request, "Unknown action provided - no action was taken", WARNING)
    return  HttpResponseRedirect("/groups/")


# **************************************
#           Server Link Views
# **************************************


@valid_user
@admin_required
def serverlinks(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("Server Links", "/serverlinks/"))
    # Using leet tables
    # If the the following submit values are in the GET paramaters, then handle them
    if "button" in request.GET.keys():
        # They clicked filter, disable, enable or delete
        if request.GET["button"] in ("Delete", "Disable", "Enable", "Erase Identity", "Reset Link"):
            if request.GET.getlist("selected"):
                # call the confirmation view - give it the button, the nouns, and a description of the nouns
                return confirm_action(request, action=request.GET["button"], objects=[xsftp.webui.models.Server.objects.get(id=sid) for sid in request.GET.getlist("selected")], description="Server", processor="/serverlinks/")
            else:
                putMessage(request, "You didn't select any Serverlinks", WARNING)
    # pop up a warning if the daemon is not running.
    if not is_daemon_running():
        putMessage(request, "The Fcombine service is not running, Server Link health data may be inaccurate.", WARNING)
    headings = []
    LeetHeading = xsftp.webui.forms.LeetHeading # could import it specifically, but this should work too
    headings.append((LeetHeading("_select_all", render_as="checkbox", sortable=False), "id"))
    headings.append((LeetHeading("Server Link Name", render_as="link"), "server_name"))
    headings.append((LeetHeading("Address"), "address"))
    headings.append((LeetHeading("Port", sortable=False), "port"))
    headings.append((LeetHeading("Type"), "type"))
    headings.append((LeetHeading("Enabled", render_as="boolean"), "enabled"))
    headings.append((LeetHeading("Status", render_as="null_boolean"), "status"))
    headings.append((LeetHeading("Last Checked", render_as="datetime"), "time_last_checked"))
    headings.append((LeetHeading("Last Seen Healthy", render_as="datetime"), "timeLastSeenHealthy"))
    headings.append((LeetHeading("SSH Fingerprint (Identity)", sortable=False), "key_fingerprint"))
    headings.append((LeetHeading("Comment"), "comment"))
    # Build the query object
    filter = ""
    if "filter" in request.GET.keys():
        filter = request.GET["filter"]
        q_object =     Q(server_name__icontains=filter) |\
                    Q(comment__icontains=filter) |\
                       Q(address__icontains=filter) |\
                    Q(type__icontains=filter) |\
                    Q(port__icontains=filter) |\
                    Q(cifs_port__icontains=filter) |\
                    Q(ftp_port__icontains=filter) |\
                    Q(key_fingerprint__icontains=filter)
        server_links = xsftp.webui.models.Server.objects.filter(q_object)
    else:
        server_links = xsftp.webui.models.Server.objects.all()
    # Now sort the server links based on the appropriate column
    # First, set sortOrder and sortCol to sensible defaults
    sortOrder = "asc"
    sortCol = "server_name"
    # Then overwrite them if they have been specified
    if "sortCol" in request.GET.keys():
        passed_sortCol = request.GET["sortCol"]
        if passed_sortCol in [h[1] for h in headings]:
            sortCol = passed_sortCol
    if "sortOrder" in request.GET.keys():
        sortOrder = request.GET["sortOrder"]
    if sortOrder == "desc":
        sortCol = "-%s" % sortCol
    # Now actually sort the server links
    server_links = server_links.order_by(sortCol)
    # Now build a list of the server link attribute tuples to put in the leet table
    serverList = odict()
    for server in server_links:
        type = server.type.upper()
        if unicode(server.id) in request.GET.getlist("selected"):
            selected = 1
        else:
            selected = 0
        if server.type == "sftp":
            key_fingerprint = server.key_fingerprint or "Unknown"
            port = server.port
        else:
            key_fingerprint = "N/A"
            if server.type == "cifs":
                port = server.cifs_port
            else:
                port = server.ftp_port
                type = "FTP"
                if server.ftp_ssl:
                    type = "FTPES"
                    if server.ftp_ssl_implicit:
                        type = "FTPS"
        if not server.enabled:
            status = None
        else:
            status = server.status == 0
        serverList[server.id] = ((server.id, selected), (server.server_name, "/serverlinks/view/%s/" % server.id), server.address, port, type, server.enabled, status, server.time_last_checked, server.timeLastSeenHealthy, key_fingerprint, server.comment)
    # Create a list of button objects
    button_list = []
    button_list.append(xsftp.webui.forms.LeetButton(value="Enable"))
    button_list.append(xsftp.webui.forms.LeetButton(value="Disable"))
    button_list.append(xsftp.webui.forms.LeetButton(value="Delete", delimiter=xsftp.webui.forms.LeetButton.SPACE))
    button_list.append(xsftp.webui.forms.LeetButton(value="Erase Identity"))
    button_list.append(xsftp.webui.forms.LeetButton(value="Reset Link"))
    totalServers = xsftp.webui.models.Server.objects.count()
    the_table = xsftp.webui.forms.LeetTable(action="/serverlinks/", headings=headings, objects=serverList.values(), filterable=True, buttons = button_list, sortable=True, filter=filter, totalObjects=totalServers, sortCol=sortCol, sortOrder=sortOrder, objectDescription="Server Link")
    params = {'title':'%s Server Links' % TITLE,
        'pageid':'serverlinks',
        'leet_table':the_table,
        }
    return render_response('serverlinks.html', request, params)


@valid_user
@admin_required
def viewserverlink(request, serverid):
    if not is_daemon_running():
        putMessage(request, "The Fcombine service is not running, Server Link health data may be inaccurate.", WARNING)
    server = xsftp.webui.models.Server.objects.get(id = serverid)
    pushBreadCrumb(request, ("View Server Link '%s'" % server.server_name, "/serverlinks/view/%s/" % serverid))
    associated_users = server.getAssociatedUsers()
    effective_write_users = server.getEffectiveWriteUsers()
    params = {'title':'%s Server Links' % TITLE,
        'pageid':'serverlinks',
        'server_to_view':server,
        'associated_users':associated_users,
        'effective_write_users':effective_write_users,
        }
    return render_response('viewserver.html', request, params)


@valid_user
@admin_required
def addserverlink(request):
    pushBreadCrumb(request, ("Add Server Link", "/serverlinks/add/"))
    new_server_form = xsftp.webui.forms.NewServerForm()
    if request.method == 'POST':
        if is_demo_user(request): return demo_user_block(request)
        new_server_form = xsftp.webui.forms.NewServerForm(request.POST)
        if new_server_form.is_valid():
            new_server_form.save()
            putMessage(request, "Successfully created new Server Link: %s" % request.POST["server_name"], INFO)
            log("user '%s' has created new Server Link: %s" % (request.user.username, request.POST["server_name"]))
            new_server_form = xsftp.webui.forms.NewServerForm()
        else:
            putMessage(request, "Please correct the errors below.", CRITICAL)
    # restrict server link addition based on number of allowed licenses
    max_allowed_serverlinks = LICENSE.get_active_license_count('SERVERLINK')
    if len(xsftp.webui.models.Server.objects.all()) >= max_allowed_serverlinks:
        putMessage(request, "You have reached your subscription limit of %s Server links. Click <a href=/subscriptions/>here</a> to see your subscriptions." % max_allowed_serverlinks, CRITICAL, no_escape=True)
        return HttpResponseRedirect('/serverlinks/')
    params = {'title':'%s Server Links' % TITLE,
        'pageid':'serverlinks',
        'new_server_form': new_server_form,
        }
    return render_response('addserver.html', request, params)


@valid_user
@admin_required
def editserverlink(request, serverid):
    server = xsftp.webui.models.Server.objects.get(id = serverid)
    pushBreadCrumb(request, ("Edit Server Link '%s'" % server.server_name, "/serverlinks/edit/%s/" % serverid))
    if request.method == "POST":
        if request.POST["button"] == "Cancel":
            # return to previous page
            popBreadCrumb(request)
            putMessage(request, "Canceled Server Link modification", WARNING)
            return HttpResponseRedirect("/serverlinks/view/%s/" % serverid)
        # They are trying to submit server data to modify against the server
        if is_demo_user(request): return demo_user_block(request)
        edit_server_form = xsftp.webui.forms.EditServerForm(request.POST)
        if edit_server_form.is_valid():
            edit_server_form.save()
            popBreadCrumb(request)
            putMessage(request, "Successfully modified Server Link %s" % server, INFO)
            log("user '%s' has modified Server Link: %s" % (request.user.username, server))
            return HttpResponseRedirect('/serverlinks/view/%s/' % serverid)
        else:
            # form was invalid
            putMessage(request, "Please correct the errors below.", CRITICAL)
    else:
        edit_server_form = xsftp.webui.forms.EditServerForm(server)
    params = {'title':'%s Server Links' % TITLE,
        'pageid':'serverlinks',
        'server_to_edit':server,
        'edit_server_form': edit_server_form,
        }
    return render_response('editserver.html', request, params)


@valid_user
@admin_required
def domodifyserverlinks(request, action):
    if request.POST["button"] != "Yes":
        putMessage(request, "%s cancelled" % action.title(), WARNING)
        return HttpResponseRedirect("/serverlinks/")
    if action == "delete":
        if is_demo_user(request): return demo_user_block(request)
        # for each selected server
        servers_to_delete = [xsftp.webui.models.Server.objects.get(id=server) for server in request.POST.getlist("selected")]
        for server in servers_to_delete:
            server.delete()
        putMessage(request, "Server Links deleted %s" % "'" + "' ,'".join([server.server_name for server in servers_to_delete]) + "'", INFO)
        log("user '%s' has deleted Server Links: %s" % (request.user.username, "'" + "' ,'".join([server.server_name for server in servers_to_delete]) + "'"))
    elif action == "disable":
        if is_demo_user(request): return demo_user_block(request)
        # disable the server, and save
        servers_to_disable = [xsftp.webui.models.Server.objects.get(id=server) for server in  request.POST.getlist("selected")]
        for server in servers_to_disable:
            server.enabled = False
            server.status = 2 #force status to 2 (MPSTATE_SM_BROKEN)
            server.save()
        putMessage(request, "Server Links disabled: %s" % "'" + "' ,'".join([server.server_name for server in servers_to_disable]) + "'", INFO)
        log("user '%s' has disabled Server Links: %s" % (request.user.username, "'" + "' ,'".join([server.server_name for server in servers_to_disable]) + "'"))
    elif action == "enable":
        if is_demo_user(request): return demo_user_block(request)
        # enable the servers and save
        servers_to_enable = [xsftp.webui.models.Server.objects.get(id=server) for server in request.POST.getlist("selected")]
        for server in servers_to_enable:
            if not server.enabled:
                server.enabled = True
                server.status = 2 #force status to 2 (MPSTATE_SM_BROKEN) since it will be in this state anyway, and wait for the remediators to correct it
                server.save()
        putMessage(request, "Server Links enabled: %s" % "'" + "' ,'".join([server.server_name for server in servers_to_enable]) + "'", INFO)
        log("user '%s' has enabled Server Links: %s" % (request.user.username, "'" + "' ,'".join([server.server_name for server in servers_to_enable]) + "'"))
    elif action == "erase identity":
        # get the list of selected server objects
        servers = [xsftp.webui.models.Server.objects.get(id=x) for x in request.POST.getlist("selected")]
        # for each selected server object
        sftp_serverlinks = []
        non_sftp_serverlinks = []
        for server in servers:
            if server.type != "sftp":
                non_sftp_serverlinks.append(server.server_name)
            else:
                sftp_serverlinks.append(server.server_name)
                # set their fingerprint to None
                server.key_fingerprint = None
                server.save()
                # and delete their entry in KNOWN_HOSTS
                delKeyFingerPrint(server)
        if non_sftp_serverlinks:
            putMessage(request, "Server Link identities not erased (key fingerprint not applicable): %s" % "'" + "' ,'".join(non_sftp_serverlinks) + "'", WARNING)
        if sftp_serverlinks:
            putMessage(request, "Server Link identities erased: %s" % "'" + "' ,'".join(sftp_serverlinks) + "'", INFO)
        log("user '%s' has erased the identity of Server Links: %s" % (request.user.username, "'" + "' ,'".join([server.server_name for server in servers]) + "'"))
    elif action == "reset link":
        # Reset the links
        servernames_to_reset = [xsftp.webui.models.Server.objects.get(id=server).server_name for server in request.POST.getlist("selected")]
        for sid in request.POST.getlist("selected"):
            os.system('sudo %swww/xsftp/webui/privexec.py --reset=%s > /dev/null 2>&1' % (xsftp.common.constants.APPDIR, sid))
        putMessage(request, "Server Links reset: %s" % "'" + "' ,'".join(servernames_to_reset) + "'", INFO)
        log("user '%s' has reset Server Links: %s" % (request.user.username, "'" + "' ,'".join(servernames_to_reset) + "'"))
    else:
        putMessage(request, "Unknown action provided - no action was taken", WARNING)
    return  HttpResponseRedirect("/serverlinks/")


# **************************************
#            Script Views
# **************************************


@valid_user
@admin_required
def scripts(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("Scripts", "/scripts/"))
    # If the the following submit values are in the GET paramaters, then handle them
    if "button" in request.GET.keys():
        # They clicked filter or delete
        if request.GET["button"] == "Delete":
            if request.GET.getlist("selected"):
                # call the confirmation view - give it the verb, the nouns, and a description of the nouns
                return confirm_action(request, action=request.GET["button"], objects=[xsftp.webui.models.Script.objects.get(id=id) for id in request.GET.getlist("selected")], description="Script", processor="/scripts/")
            else:
                putMessage(request, "You didn't select any Scripts to %s" % request.GET["button"].lower(), WARNING)
    headings = []
    LeetHeading = xsftp.webui.forms.LeetHeading # could import it specifically, but this should work too
    headings.append((LeetHeading("_select_all", render_as="checkbox", sortable=False), "id"))
    headings.append((LeetHeading("Script Name", render_as="link"), "script_name"))
    headings.append((LeetHeading("File"), "file"))
    headings.append((LeetHeading("Comment"), "comment"))
    # Build the query object
    filter = ""
    if "filter" in request.GET.keys():
        filter = request.GET["filter"]
        q_object =     Q(script_name__icontains=filter) |\
                    Q(file__icontains=filter) |\
                       Q(comment__icontains=filter)
        scripts = xsftp.webui.models.Script.objects.filter(q_object)
    else:
        scripts = xsftp.webui.models.Script.objects.all()
    # Now sort the users based on the appropriate column
    # First, set sortOrder and sortCol to sensible defaults
    sortOrder = "asc"
    sortCol = "script_name"
    # Then overwrite them if they have been specified
    if "sortCol" in request.GET.keys():
        passed_sortCol = request.GET["sortCol"]
        if passed_sortCol in [h[1] for h in headings]:
            sortCol = passed_sortCol
    if "sortOrder" in request.GET.keys():
        sortOrder = request.GET["sortOrder"]
    if sortOrder == "desc":
        sortCol = "-%s" % sortCol
    # Now actually sort the scripts...
    scripts = scripts.order_by(sortCol)
    # Now build a list of the script attribute tuples to put in the leet table
    scriptList = odict()
    for script in scripts:
        if unicode(script.id) in request.GET.getlist("selected"):
            selected = 1
        else:
            selected = 0
        scriptList[script.id] = ((script.id, selected), (script.script_name, "/scripts/view/%s/" % script.id), os.path.basename(script.file.name), script.comment)
    button_list = []
    button_list.append(xsftp.webui.forms.LeetButton(value="Delete"))
    totalScripts = xsftp.webui.models.Script.objects.count()
    the_table = xsftp.webui.forms.LeetTable(action="/scripts/", headings=headings, objects=scriptList.values(), filterable=True, sortable=True, buttons=button_list, filter=filter, totalObjects=totalScripts, sortCol=sortCol, sortOrder=sortOrder, objectDescription="Script")
    params = {'title':'%s Scripts' % TITLE,
        'pageid':'scripts',
        'leet_table':the_table,
        }
    return render_response('scripts.html', request, params)


@valid_user
@admin_required
def domodifyscripts(request, action):
    # Check if the user has the priveleges to modify each script
    if request.POST["button"] != "Yes":
        putMessage(request, "%s cancelled" % action.title(), WARNING)
        return HttpResponseRedirect("/scripts/")
    if is_demo_user(request): return demo_user_block(request)
    if action == "delete":
        scripts_to_delete = [xsftp.webui.models.Script.objects.get(id=script)  for script in request.POST.getlist("selected")]
        # for each selected script
        for script in scripts_to_delete:
            # Delete the script
            script.delete()
        putMessage(request, "Scripts deleted: %s" % "'" + "' ,'".join([script.script_name for script in scripts_to_delete]) + "'", INFO)
        log("user '%s' has deleted Scripts: %s" % (request.user.username, "'" + "' ,'".join([script.script_name for script in scripts_to_delete]) + "'"))
    else:
        putMessage(request, "Unknown action provided - no action was taken", WARNING)
    return  HttpResponseRedirect("/scripts/")


@valid_user
@admin_required
def viewscript(request, scriptid):
    script = xsftp.webui.models.Script.objects.get(id = scriptid)
    pushBreadCrumb(request, ("View Script '%s'" % script.script_name, "/scripts/view/%s/" % scriptid))
    associated_users = script.getAssociatedUsers()
    params = {'title':'%s View Script' % TITLE,
        'pageid':'scripts',
        'script_to_view':script,
        'exec_users':script.execUsers.all(),
        'exec_groups':script.execGroups.all(),
        'associated_users':associated_users,
        }
    return render_response('viewscript.html', request, params)


@valid_user
@admin_required
def getscript(request, scriptid):
    script = xsftp.webui.models.Script.objects.get(id = scriptid)
    # read the file
    f = file(script.file.path, 'r')
    content = f.read()
    f.close()
    response = HttpResponse()
    response.content = content
    response["Content-Disposition"] = "attachment; filename=%s" % os.path.basename(script.file.name)
    log("user '%s' has downloaded Script: %s" % (request.user.username, script.script_name))
    return response

@valid_user
@admin_required
def addscript(request):
    pushBreadCrumb(request, ("Add Script", "/scripts/add/"))
    newscriptform = xsftp.webui.forms.NewScriptForm()
    if request.method == 'POST':
        if is_demo_user(request): return demo_user_block(request)
        newscriptform = xsftp.webui.forms.NewScriptForm(request.POST, request.FILES)
        if newscriptform.is_valid():
            newscriptform.save()
            putMessage(request, "Successfully created new script: %s" % request.POST["script_name"], INFO)
            log("user '%s' has created new Script: %s" % (request.user.username, request.POST["script_name"]))
            newscriptform = xsftp.webui.forms.NewScriptForm()
        else:
            putMessage(request, "Please correct the errors below.", CRITICAL)
    params = {'title':'%s Add New Script' % TITLE,
        'pageid':'scripts',
        'newscriptform':newscriptform,
        }
    return render_response("addscript.html", request, params)

@valid_user
@admin_required
def editscript(request, scriptid):
    script = xsftp.webui.models.Script.objects.get(id = scriptid)
    pushBreadCrumb(request, ("Edit Script '%s'" % script.script_name, "/scripts/edit/%s/" % scriptid))
    if request.method == "POST":
        if request.POST["button"] == "Cancel":
            # return to previous page
            popBreadCrumb(request)
            putMessage(request, "Canceled Script modification", WARNING)
            return HttpResponseRedirect("/scripts/view/%s/" % scriptid)
        # They are trying to submit data to modify against the script
        if is_demo_user(request): return demo_user_block(request)
        edit_script_form = xsftp.webui.forms.EditScriptForm(request.POST, request.FILES)
        if edit_script_form.is_valid():
            messages = edit_script_form.save()
            popBreadCrumb(request)
            putMessage(request, "Successfully modified script %s" % script, INFO)
            log("user '%s' has modified Script: %s" % (request.user.username, script))
            for message in messages:
                putMessage(request, message, WARNING)
            return HttpResponseRedirect('/scripts/view/%s/' % scriptid)
        else:
            # form was invalid
            putMessage(request, "Please correct the errors below.", CRITICAL)
    else:
        edit_script_form = xsftp.webui.forms.EditScriptForm(script)
    params = {'title':'%s Edit Script' % TITLE,
        'pageid':'scripts',
        'script_to_edit':script,
        'edit_script_form': edit_script_form,
        }
    return render_response('editscript.html', request, params)



# **************************************
#       Job Views (Admin and Operator)
# **************************************

@valid_user
@admin_required
def jobsAll(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("All Jobs", "/jobs/all/"))
    return jobs(request, allJobs=True)

@valid_user
def jobs(request, allJobs=False):
    if not allJobs:
        clearBreadCrumbs(request)
        pushBreadCrumb(request, ("My Jobs", "/jobs/"))
    # Using leet tables
    # If the the following submit values are in the GET paramaters, then handle them
    if "button" in request.GET.keys():
        # They clicked filter, disable, enable or delete
        if request.GET["button"] in ("Delete", "Disable", "Enable"):
            if request.GET.getlist("selected"):
                # call the confirmation view - give it the verb, the nouns, and a description of the nouns
                if not allJobs:
                    processor = "/jobs/"
                else:
                    processor = "/jobs/all/"
                return confirm_action(request, action=request.GET["button"], objects=[xsftp.webui.models.Job.objects.get(id=jid) for jid in request.GET.getlist("selected")], description="Job", processor=processor)
            else:
                putMessage(request, "You didn't select any Jobs to %s" % request.GET["button"].lower(), WARNING)
    headings = []
    LeetHeading = xsftp.webui.forms.LeetHeading # could import it specifically, but this should work too
    headings.append((LeetHeading("_select_all", render_as="checkbox", sortable=False), "id"))
    headings.append((LeetHeading("Job Name", render_as="link"), "job_name"))
    if allJobs:
        # all jobs was selected, so include the owner column
        headings.append((LeetHeading("Owner", render_as="link"), "owner"))
    headings.append((LeetHeading("Running Now", render_as="jobstatus"), "running_now"))
    headings.append((LeetHeading("Last Run Status", render_as="null_boolean"), "last_run_status"))
    headings.append((LeetHeading("Enabled", render_as="boolean"), "enabled"))
    headings.append((LeetHeading("Sanity", render_as="boolean"), "errorFlags"))
    headings.append((LeetHeading("Last Seen Sane", render_as="datetime"), "timeLastSeenSane"))
    headings.append((LeetHeading("Schedule Type"), "schedule_type"))
    headings.append((LeetHeading("Source", render_as="link"), "source_server"))
    headings.append((LeetHeading("Destination", render_as="link"), "dest_server"))
    headings.append((LeetHeading("Comment"), "comment"))
    # Build the query object
    filter = ""
    if "filter" in request.GET.keys():
        filter = request.GET["filter"]
        q_object =     Q(job_name__icontains=filter) |\
                    Q(owner__username__icontains=filter) |\
                       Q(comment__icontains=filter) |\
                    Q(source_server__server_name__icontains=filter) |\
                    Q(dest_server__server_name__icontains=filter)
        jobs = xsftp.webui.models.Job.objects.filter(q_object)
    else:
        jobs = xsftp.webui.models.Job.objects.all()

    if allJobs:
        pageHeading = "All Jobs"
        action = "/jobs/all/"
        pageid = "alljobs"
    else:
        jobs = jobs.filter(owner=request.user)
        pageHeading = "My Jobs"
        action = "/jobs/"
        pageid = "myjobs"
    totalJobs = jobs.count()
    # Now sort the users based on the appropriate column
    # First, set sortOrder and sortCol to sensible defaults
    sortOrder = "asc"
    sortCol = "job_name"
    # Then overwrite them if they have been specified
    if "sortCol" in request.GET.keys():
        passed_sortCol = request.GET["sortCol"]
        if passed_sortCol in [h[1] for h in headings]:
            sortCol = passed_sortCol
    if "sortOrder" in request.GET.keys():
        sortOrder = request.GET["sortOrder"]
    if sortOrder == "desc":
        sortCol = "-%s" % sortCol
    # Now actually sort the jobs ...
    jobs = jobs.order_by(sortCol)
    # Now build a list of the job attribute tuples to put in the leet table
    jobList = odict()
    for job in jobs:
        if unicode(job.id) in request.GET.getlist("selected"):
            selected = 1
        else:
            selected = 0
        # if alljobs is selected
        if allJobs:
            # include the owner column
            if job.owner:
                ownerField = (job.owner, "/users/view/%s/" % job.owner.id)
            else:
                ownerField = ("","")
            jobList[job.id] = ((job.id, selected), (job.job_name, "view/%s/" % job.id), ownerField, job.running_now, job.last_run_status, job.enabled, job.errorFlags==0, job.timeLastSeenSane, job.scheduleTypeString(), ((job.source_server or ""), "/serverlinks/view/%s/" % (not job.source_server or job.source_server.id)), ((job.dest_server or ""), "/serverlinks/view/%s/" % (not job.dest_server or job.dest_server.id)), job.comment)
        else:
            # myjobs was selected, omit the owner column
            jobList[job.id] = ((job.id, selected), (job.job_name, "view/%s/" % job.id), job.running_now, job.last_run_status, job.enabled, job.errorFlags==0, job.timeLastSeenSane, job.scheduleTypeString(), ((job.source_server or ""), "/myserverlinks/view/%s/" % (not job.source_server or job.source_server.id)), ((job.dest_server or ""), "/myserverlinks/view/%s/" % (not job.dest_server or job.dest_server.id)), job.comment)
    button_list = []
    button_list.append(xsftp.webui.forms.LeetButton(value="Enable"))
    button_list.append(xsftp.webui.forms.LeetButton(value="Disable"))
    button_list.append(xsftp.webui.forms.LeetButton(value="Delete"))
    the_table = xsftp.webui.forms.LeetTable(action=action, headings=headings, objects=jobList.values(), filterable=True, sortable=True, buttons=button_list, filter=filter, totalObjects=totalJobs, sortCol=sortCol, sortOrder=sortOrder, objectDescription="Job")
    params = {
        'pageid':pageid,
        'leet_table':the_table,
        'pageHeading':pageHeading,
        'allJobs':allJobs,
        }
    if allJobs:
        params["title"] = "%s All Jobs" % TITLE
    else:
        params["title"] = "%s Jobs" % TITLE
    return render_response('jobs.html', request, params)


@valid_user
def domodifyjobs(request, allJobs, action):
    if allJobs:
        redirect = "/jobs/all/"
    else:
        redirect = "/jobs/"
    if not request.user.is_staff:
        for jid in request.POST.getlist("selected"):
            job = xsftp.webui.models.Job.objects.get(id=jid)
            if job.owner != request.user:
                putMessage(request, "You do not have permission to modify at least one of the selected jobs",CRITICAL)
                return HttpResponseRedirect(redirect)
    if request.POST["button"] != "Yes":
        putMessage(request, "%s cancelled" % action.title(), WARNING)
        return HttpResponseRedirect(redirect)
    if action == "delete":
        jobs_to_delete = [xsftp.webui.models.Job.objects.get(id=job) for job in request.POST.getlist("selected")]
        # for each selected job
        for job in jobs_to_delete:
            job.delete()
        putMessage(request, "Jobs deleted: %s" % "'" + "' ,'".join([job.job_name for job in jobs_to_delete]) + "'", INFO)
        log("user '%s' has deleted Jobs: %s" % (request.user.username, "'" + "' ,'".join([job.job_name for job in jobs_to_delete]) + "'"))
    elif action == "disable":
        jobs_to_disable = [xsftp.webui.models.Job.objects.get(id=job) for job in request.POST.getlist("selected")]
        # disable the job, and save
        for job in jobs_to_disable:
            job.enabled = False
            job.save()
        putMessage(request, "Jobs disabled: %s" % "'" + "' ,'".join([job.job_name for job in jobs_to_disable]) + "'", INFO)
        log("user '%s' has disabled Jobs: %s" % (request.user.username, "'" + "' ,'".join([job.job_name for job in jobs_to_disable]) + "'"))
    elif action == "enable":
        jobs_to_enable = [xsftp.webui.models.Job.objects.get(id=job) for job in request.POST.getlist("selected")]
        # enable the jobs and save
        for job in jobs_to_enable:
            job.enabled = True
            job.save()
        putMessage(request, "Jobs enabled: %s" % "'" + "' ,'".join([job.job_name for job in jobs_to_enable]) + "'", INFO)
        log("user '%s' has enabled Jobs: %s" % (request.user.username, "'" + "' ,'".join([job.job_name for job in jobs_to_enable]) + "'"))
    else:
        putMessage(request, "Unknown action provided - no action was taken", WARNING)
    return HttpResponseRedirect(redirect)

@valid_user
def killjob(request, jobid, allJobs):
    job = xsftp.webui.models.Job.objects.get(id = jobid)
    if allJobs:
        pageid = "alljobs"
        action = "/jobs/all/kill/%s/" % job.id
        pushBreadCrumb(request, ("Kill Job '%s'" % job.job_name, action))
        redirect = "/jobs/all/view/%s/" % jobid
    else:
        pageid = "myjobs"
        action = "/jobs/kill/%s/" % job.id
        pushBreadCrumb(request, ("Kill Job '%s'" % job.job_name, action))
        redirect = "/jobs/view/%s/" % jobid
    if not request.user.is_staff and not request.user == job.owner:
        putMessage(request, "You do not have permission to kill the selected job",CRITICAL)
        return HttpResponseRedirect(redirect)
    # If they have POSTed to get here, they've probably come from the confirmation page
    if request.method == "POST":
        # Check which button they clicked
        if request.POST["button"] == "Yes":
            # If job is still actually running
            if job.running_now:
                # Kill the job
                job.running_now = None # 1 (or True) running now, 0 (or False), not running, and None = terminating.
                job.save()
                subprocess.call(["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--killjob", str(job.id)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                putMessage(request, "A Kill signal has been sent to job '%s'" % job, INFO)
            else:
                putMessage(request, "Job '%s' is no longer currently running. Kill aborted." % job, WARNING)
        else:
            putMessage(request, "Kill Job '%s' cancelled" % job, WARNING)
        popBreadCrumb(request)
        return HttpResponseRedirect(redirect)
    # send them to the confirmation page
    params = {'title':'Kill Job',
        'pageid':pageid,
        'job_to_kill':job,
        'action':action,
        }
    return render_response('killjob.html', request, params)
    

@valid_user
def viewjob(request, jobid, allJobs):
    job = xsftp.webui.models.Job.objects.get(id = jobid)
    if not allJobs:
        # ensure the operator can only see the job if they own it
        if not (request.user == job.owner):
            return HttpResponseRedirect("/jobs/")
    if allJobs:
        # ensure that they are an admin
        if not request.user.is_staff:
            return HttpResponseRedirect("/jobs/")
    # ensure they go back to the right place when they click the "View Jobs" link button from the viewjob tempalte
    if allJobs:
        pushBreadCrumb(request, ("View Job '%s'" % job.job_name, "/jobs/all/view/%s/" % jobid))
        action = "/jobs/all/"
        serverlinksProcessor = "/serverlinks/view/"
        scriptsProcessor = "/scripts/view/"
        pageid = "alljobs"
    else:
        pushBreadCrumb(request, ("View Job '%s'" % job.job_name, "/jobs/view/%s/" % jobid))
        action = "/jobs/"
        serverlinksProcessor = "/myserverlinks/view/"
        scriptsProcessor = "/myscripts/view/"
        pageid = "myjobs"
    params = {'title':'%s Jobs' % TITLE,
        'pageid':pageid,
        'job_to_view':job,
        'action':action,
        'serverlinksProcessor':serverlinksProcessor,
        'scriptsProcessor':scriptsProcessor,
        'is_staff':request.user.is_staff,
        }
    return render_response('viewjob.html', request, params)

@valid_user
def addjob(request):
    # first check if the user can actually write to any servers. if not, send them back with an error.
    if not request.user.userprofile.getEffectiveWriteServers():
        if not request.user.is_staff:
            putMessage(request, "You can not add a new job because you do not have write permissions to any server links. Please contact an administrator and request write permissions on one or more server links and try again.", CRITICAL)
        else:
            putMessage(request, "You can not add a new job because you do not have write permissions to any server links.", CRITICAL)
        return HttpResponseRedirect("/jobs/")
    pushBreadCrumb(request, ("Add Job", "/jobs/add/"))
    if request.method == 'POST':
        if request.POST["button"] == "Cancel":
            # return to previous page
            popBreadCrumb(request)
            putMessage(request, "Canceled adding a new Job", WARNING)
            return HttpResponseRedirect("/jobs/")
        new_job_form = xsftp.webui.forms.NewJobForm(request.user, request.POST)
        glob_prefixes = list()
        for field_name in request.POST.keys():
            if field_name.endswith("-glob"):
                glob_prefixes.append(field_name[:field_name.find("-")])
        glob_prefixes.sort(lambda x,y: int(x)-int(y))
        glob_forms = [xsftp.webui.forms.GlobForm(request.POST, prefix=x) for x in glob_prefixes]
        if new_job_form.is_valid() and reduce(lambda x, y: x and y, [gf.is_valid() for gf in glob_forms]): # this is python magic. Enhoy spending 15 years trying to work out how the fsck this works.
            new_job = new_job_form.save()
            for glob_form in glob_forms:
                globObject = glob_form.save()
                globObject.job_id = new_job.id
                globObject.save()
            putMessage(request, "Successfully created new job: %s" % request.POST["job_name"], INFO)
            log("user '%s' has created new Job: %s" % (request.user.username, request.POST["job_name"]))
            new_job_form = xsftp.webui.forms.NewJobForm(request.user)
            glob_forms = [xsftp.webui.forms.GlobForm(prefix="0"),]
        else:
            putMessage(request, "Please correct the errors below.", CRITICAL)
    else:
        new_job_form = xsftp.webui.forms.NewJobForm(request.user)
        glob_forms = [xsftp.webui.forms.GlobForm(prefix="0"),] # Needs to be a list, even though there's only one of them
    params = {'title':'%s Add Job' % TITLE,
        'pageid':'myjobs',
        'new_job_form': new_job_form,
        'glob_forms': glob_forms,
        }
    return render_response('addjob.html', request, params)


@valid_user
def editjob(request, jobid, allJobs):
    job = xsftp.webui.models.Job.objects.get(id = jobid)
    if not request.user.is_staff and job not in request.user.job_set.all():
        putMessage(request, "It seems you tried to edit a job which is not yours", CRITICAL)
        return HttpResponseRedirect("/jobs/")
    if allJobs:
        pushBreadCrumb(request, ("Edit Job '%s'" % job.job_name, "/jobs/all/edit/%s/" % job.id))
        pageid = "alljobs"
        action = "/jobs/all/"
    else:
        pushBreadCrumb(request, ("Edit Job '%s'" % job.job_name, "/jobs/edit/%s/" % job.id))
        pageid = "myjobs"
        action = "/jobs/"
    if not job.running_now == False:
        popBreadCrumb(request)
        putMessage(request, "Job cannot be edited whilst it is running", WARNING)
        return HttpResponseRedirect("%sview/%s/" % (action, job.id))
    if request.method == "POST":
        if request.POST["button"] == "Cancel":
            # return to previous page
            popBreadCrumb(request)
            putMessage(request, "Canceled Job modification", WARNING)
            return HttpResponseRedirect("%sview/%s/" % (action, job.id))
        # They are trying to submit job data to modify against the job
        newPostData = request.POST.copy()
        newPostData["owner_id"] = job.owner_id
        newPostData["id"] = job.id
        edit_job_form = xsftp.webui.forms.EditJobForm(request.user, newPostData)
        glob_prefixes = list()
        for field_name in request.POST.keys():
            if field_name.endswith("-glob"):
                glob_prefixes.append(field_name[:field_name.find("-")])
        glob_prefixes.sort(lambda x,y: int(x)-int(y))
        edit_glob_forms = [xsftp.webui.forms.GlobForm(request.POST, prefix=x) for x in glob_prefixes]
        if edit_job_form.is_valid() and reduce(lambda x, y: x and y, [gf.is_valid() for gf in edit_glob_forms]): # this is python magic. Enjoy spending 15 years trying to work out how the fuck this works.
            for glob in job.glob_set.all():
                glob.delete()
            edit_job_form.save(job.id)
            for edit_glob_form in edit_glob_forms:
                globObject = edit_glob_form.save()
                globObject.job_id = job.id
                globObject.save()
            popBreadCrumb(request)
            putMessage(request, "Successfully modified job %s" % job.job_name, INFO)
            log("user '%s' has modified Job: %s" % (request.user.username, job.job_name))
            if allJobs:
                return HttpResponseRedirect("/jobs/all/view/%s/" % job.id)
            else:
                return HttpResponseRedirect('/jobs/view/%s/' % job.id)
        else:
            putMessage(request, "Please correct the errors below.", CRITICAL)
    else:
        # setup a dictionary populated with the pre-selected choices of the correct types (ie. strings) so that our form validation doesn't spit.
        jobDict = job.__dict__.copy()
        jobDict["job_owner"] = str(jobDict["owner_id"])
        jobDict["source_server"] = str(jobDict["source_server_id"])
        jobDict["dest_server"] = str(jobDict["dest_server_id"])
        jobDict["advanced"] = " ".join([job.minute, job.hour, job.day, job.month, job.dow])
        jobDict["schedule_type"] = str(job.schedule_type)
        jobDict["exist_action"] = str(jobDict["exist_action"])
        jobDict["pre_script"] = str(jobDict["pre_script_id"] or "")
        jobDict["post_script"] = str(jobDict["post_script_id"] or "")
        jobDict["alert_groups_on_success"] = [str(group.id) for group in job.alert_groups_on_success.all()]
        jobDict["alert_groups_on_fail"] = [str(group.id) for group in job.alert_groups_on_fail.all()]
        edit_job_form = xsftp.webui.forms.EditJobForm(request.user, jobDict)
        edit_glob_forms = [xsftp.webui.forms.EditGlobForm(glob.__dict__) for glob in job.glob_set.all()]
        #putMessage(request, jobDict, DEBUG)
    params = {'title':'%s Edit Job' % TITLE,
        'action':action,
        'pageid':pageid,
        'job_to_edit':job,
        'edit_job_form': edit_job_form,
        'edit_glob_forms': edit_glob_forms,
        }
    return render_response('editjob.html', request, params)


@valid_user
def runjob(request, jobid, allJobs):
    '''
    This view is invoked only when the "Run Now" button is selected on the View Job page, and will invoke jobrunner.
    Jobrunner is normally invoked by cron according to a jobs defined schedule.
    '''
    job = xsftp.webui.models.Job.objects.get(id = jobid)
    if not request.user.is_staff and job not in request.user.job_set.all():
        putMessage(request, "It seems you tried to run a job which is not yours", CRITICAL)
        return HttpResponseRedirect("/jobs/")
    if allJobs:
        pageid = "alljobs"
        action = "/jobs/all/"
    else:
        pageid = "myjobs"
        action = "/jobs/"
    if not job.running_now == False:
        putMessage(request, "Job cannot be run whilst it is already running", WARNING)
        return HttpResponseRedirect("%sview/%s/" % (action, job.id))
    if job.errorFlags:
        putMessage(request, "Job cannot be run whilst it fails sanity checks.", WARNING)
        return HttpResponseRedirect("%sview/%s/" % (action, job.id))
    # Run the job
    subprocess.call(["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--runjob", str(job.id)], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    putMessage(request, "A Start signal has been sent to job '%s'" % job, INFO)
    return HttpResponseRedirect("%sview/%s/" % (action, job.id))

# **************************************
#          Reporting Views
# **************************************


@valid_user
@admin_required
def reporting(request): #TODO consider for implementation in future release.
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("Reporting", "/reporting/"))
    params = {'title':'%s Reporting' % TITLE,
        'pageid':'reporting',
        }
    return render_response('reporting.html', request, params)


# **************************************
#         Configuration Views
# **************************************


@valid_user
@admin_required
def configuration(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("Configuration", "/configuration/"))
    configuration = xsftp.webui.models.Configuration.objects.all()[0]
    # obtain system details from database
    params = {'title':'%s Configuration' % TITLE,
        'pageid':'configuration',
        'config':configuration,
        }
    return render_response('configuration.html', request, params)

@valid_user
@admin_required
def editconfiguration(request):
    config = xsftp.webui.models.Configuration.objects.all()[0]
    pushBreadCrumb(request, ("Edit Configuration", "/configuration/edit/"))
    if request.method == "POST":
        if request.POST["button"] == "Cancel":
            # return to previous page
            popBreadCrumb(request)
            putMessage(request, "Canceled system configuration modification", WARNING)
            return HttpResponseRedirect("/configuration/")
        if is_demo_user(request): return demo_user_block(request)
        edit_config_form = xsftp.webui.forms.EditConfigForm(request.POST)
        if edit_config_form.is_valid():
            # check if ip address, subnet mask or gateway changed, and of so, alert user that a reboot is required.
            if config.ip_address != edit_config_form.cleaned_data["ip_address"] or config.subnet_mask != edit_config_form.cleaned_data["subnet_mask"] or config.default_gateway != edit_config_form.cleaned_data["default_gateway"]:
                putMessage(request, "YOU MUST RESTART THIS SYSTEM FOR THE NEW CONFIGURATION TO TAKE EFFECT", WARNING)
            edit_config_form.save()
            popBreadCrumb(request)
            putMessage(request, "Successfully modified system configuration", INFO)
            log("user '%s' has modified system-wide configuration." % request.user.username)
            return HttpResponseRedirect('/configuration/')
        else:
            putMessage(request, "Please correct the errors below.", CRITICAL)
    else:
        edit_config_form = xsftp.webui.forms.EditConfigForm(config)
    params = {
        'title':'%s Edit Configuration' % TITLE,
        'pageid':'configuration',
        'edit_config_form':edit_config_form,
        }
    return render_response('editconfig.html', request, params)


@valid_user
@admin_required
def getpublickey(request, keytype):
    if not keytype in ['ssh2', 'rfc4716']:
        raise Http404
    source_file = "%setc/xsftp/keys/xsftp_key.pub" % xsftp.common.constants.APPDIR
    f = file(source_file, 'r')
    keydata = f.read()
    f.close()
    key = xsftp.webui.forms.parse_pubkey(keydata)
    comment = "%s@%s" % (xsftp.webui.models.Configuration.objects.all()[0].device_name, xsftp.webui.models.Configuration.objects.all()[0].ip_address)
    base64data = key.get_base64()
    keydata = ""
    if keytype == 'ssh2':
        keydata = "%s %s %s" % (key.type, base64data, comment)
    else:
        base64lines = []
        base64data = key.get_base64()
        while base64data:
            base64lines.append(base64data[:64])
            base64data = base64data[64:]
        base64data = "\n".join(base64lines)
        keydata='---- BEGIN SSH2 PUBLIC KEY ----\nComment: "%s"\n%s\n---- END SSH2 PUBLIC KEY ----\n' % (comment, base64data)
    response = HttpResponse()
    response.content = keydata
    response["Content-Disposition"] = "attachment; filename=fcombine_%s_pubkey.pub" % keytype
    log("user '%s' has downloaded the Global Server Link Public Key." % request.user.username)
    return response


@valid_user
@admin_required
def testmail(request):
    '''
    Sends a test email to the requesting user
    '''
    # first check if an smtp server has been configured
    smtp_server = xsftp.webui.models.Configuration.objects.all()[0].smtp_server
    smtp_port = xsftp.webui.models.Configuration.objects.all()[0].smtp_port
    if not smtp_server:
        putMessage(request, "Can not send test email because the SMTP Server is not configured", CRITICAL)
        return HttpResponseRedirect("/configuration/")
    to_address = request.user.email
    if not to_address:
        putMessage(request, "Can not send test email because you have not configured an email address in your user profile.", CRITICAL)
        return HttpResponseRedirect("/configuration/")
    if is_demo_user(request): return demo_user_block(request)
    name = request.user.userprofile.getNameString()
    from_address = xsftp.webui.models.Configuration.objects.all()[0].smtp_from_address or "admin@%s" % xsftp.webui.models.Configuration.objects.all()[0].ip_address
    device_name = xsftp.webui.models.Configuration.objects.all()[0].device_name
    ip_address = xsftp.webui.models.Configuration.objects.all()[0].ip_address
    subject = "Test email from Fcombine Fcombine: %s" % device_name
    message = "\nThis is an automatic test email sent by the Fcombine Fcombine identified by:\n\nDevice Name:\t%(device_name)s\nIP address:\t%(ip_address)s\n\nIf you receive this message, the email settings on this system are configured correctly.\n" % {"name":name, "device_name": device_name, "ip_address":ip_address }
    try:
        smtpcon = django.core.mail.SMTPConnection(host=smtp_server, port=smtp_port)
        email = django.core.mail.EmailMessage(subject=subject, body=message, from_email=from_address, to=[to_address], connection=smtpcon)
        log("email.message")
        log(django.core.mail.DNS_NAME._fqdn)
        email.send()
    except socket.error, e:
        putMessage(request, "Error sending email: %s" % e[1], CRITICAL)
        log("test email attempt to user '%s' failed: %s" % (request.user.username, e))
        return HttpResponseRedirect("/configuration/")
    except socket.gaierror, e:
        putMessage(request, "Error sending email: %s" % e[1], CRITICAL)
        log("test email attempt to user '%s' failed: %s" % (request.user.username, e))
        return HttpResponseRedirect("/configuration/")
    except smtplib.SMTPException, e:
        putMessage(request, "Error sending email: %s" % e, CRITICAL)
        log("test email attempt to user '%s' failed: %s" % (request.user.username, e))
        return HttpResponseRedirect("/configuration/")
    except:
        putMessage(request, "Unexpected error sending email, please try adjusting your settings and/or trying again.", CRITICAL)
        log("test email attempt to user '%s' failed." % request.user.username)
        return HttpResponseRedirect("/configuration/")
    try:
        smtpcon.close()
    except:
        pass # fail silently on close()
    putMessage(request, "Test email sent", INFO)
    log("test email attempt to user '%s' successfully sent." % request.user.username)    
    return HttpResponseRedirect("/configuration/")


@valid_user
@admin_required
def testsyslog(request):
    '''
    Sends a test log line to syslog with the intention of testing a remote syslog server.
    '''
    if not xsftp.webui.models.Configuration.objects.all()[0].remote_syslog_server:
        putMessage(request, "Can not send test log because the Remote Syslog Server is not configured", CRITICAL)
        return HttpResponseRedirect("/configuration/")
    if is_demo_user(request): return demo_user_block(request)
    if request.user.first_name:
        name = "%s %s" % (request.user.first_name, request.user.last_name)
    else:
        name = request.user.username
    device_name = xsftp.webui.models.Configuration.objects.all()[0].device_name
    ip_address = xsftp.webui.models.Configuration.objects.all()[0].ip_address
    message = "This is a test log message sent by user '%s' from the Fcombine Fcombine system identified by device_name='%s' and ip_address='%s'" % (name, device_name, ip_address)
    log(message)
    putMessage(request, "Test log sent", INFO)
    log("test syslog message sent to server '%s' by user '%s'" % (xsftp.webui.models.Configuration.objects.all()[0].remote_syslog_server, request.user.username))
    return HttpResponseRedirect("/configuration/")


@valid_user
@admin_required
def restart(request):
    if request.POST:
        if request.POST["button"] == "Restart":
            if is_demo_user(request): return demo_user_block(request)
            log("user '%s' has rebooted the Fcombine: %s" % (request.user.username, xsftp.webui.models.Configuration.objects.all()[0].device_name))
            subprocess.Popen(['sudo %swww/xsftp/webui/privexec.py --restart > /dev/null 2>&1' % xsftp.common.constants.APPDIR], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, close_fds=True)
            # redirect them to the restart-in-progress page, so that if they try refresh after reboot is done, they won't inadvertantly reboot the system again.
            return HttpResponseRedirect("/configuration/restartinprogress/")
        else:
            putMessage(request, "Cancelled system restart", WARNING)
            return HttpResponseRedirect("/configuration/")
    params = {'title':'%s Configuration: Restart System' % TITLE,
    'pageid':'configuration',
    }
    return render_response('confirmrestart.html', request, params)

@valid_user
@admin_required
def restartinprogress(request):
    params = {'title':'%s Configuration: Restarting System' % TITLE,
    'pageid':'configuration',
    }
    return render_response('restart_in_progress.html', request, params)


# **************************************
#         Systemlog Views
# **************************************


@valid_user
@admin_required
def systemlog(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("System Log", "/systemlog/"))
    # ensure the log file has corect perms
    os.system("sudo %swww/xsftp/webui/privexec.py --setlogperm > /dev/null 2>&1" % xsftp.common.constants.APPDIR)
    f = file(xsftp.webui.constants.SYSLOG_LOG_FILE, "r")
    logLines = f.readlines()[-100:] # store the last 100 lines of the log. if this is not enough, they can go to archives and get the whole thing.
    f.close()
    splitLogLines = [logLine.split() for logLine in logLines]
    # show newest log at top of list.
    splitLogLines.reverse()
    logRows = []
    logHeader = ['Month', 'Day', 'Time', "Hostanme", "ID", "Message"]    
    logRows.append(logHeader)
    for line in splitLogLines:
        if len(line) < 5:
            logRows.append( ["", "", "", "", "", " ".join(line)] )
        elif line[4] != "last":
            logRows.append( [line[0], line[1], line[2], line[3], line[4], " ".join(line[5:])] )
        else:
            logRows.append( [line[0], line[1], line[2], line[3], "", " ".join(line[4:])] )
    # obtain system details from database
    params = {'title':'%s System Log' % TITLE,
        'pageid':'systemlog',
        'logrows':logRows
        }
    return render_response('systemlog.html', request, params)



@valid_user
@admin_required
def getsystemlog(request):
    source_file = xsftp.webui.constants.SYSLOG_LOG_FILE
    # ensure the log file has corect perms
    os.system("sudo %swww/xsftp/webui/privexec.py --setlogperm > /dev/null 2>&1" % xsftp.common.constants.APPDIR)
    file_name = xsftp.webui.constants.SYSLOG_LOG_FILE.split("/")[-1]
    f = file(source_file, 'r')
    content = f.read()
    f.close()
    response = HttpResponse()
    response.content = content
    response["Content-Disposition"] = "attachment; filename=%s" % file_name
    log("user '%s' has downloaded System Log" % request.user.username)
    return response


@valid_user
@admin_required
def systemlogarchive(request):
    import glob
    pushBreadCrumb(request, ("System Log Atchive", "/systemlog/archive/"))
    # get all log filenames
    logFileNames = glob.glob(xsftp.webui.constants.SYSLOG_LOG_FILE + "*")
    # get last-mofidied date of each file and create a [(filename, fileModTime), ...] list:
    logFiles = []
    for logFileName in logFileNames:
        logFiles.append((logFileName.split("/")[-1], datetime.fromtimestamp( os.stat(logFileName).st_mtime ), str(os.stat(logFileName).st_size/1024) + " kB" ))
    # sort the lsit based on modification date
    logFiles = sorted(logFiles, key=operator.itemgetter(1))
    logFiles.reverse()
    params = {'title':'%s System Log Archive' % TITLE,
        'pageid':'systemlog',
        'logfiles': logFiles
        }
    return render_response('systemlogarchive.html', request, params)


@valid_user
@admin_required
def getarchivedlog(request, filename):
    import glob
    #putMessage(request, "you wana download this: %s" % filename, DEBUG)
    source_file = xsftp.webui.constants.SYSLOG_LOG_FILE
    # ensure the log file has corect perms
    os.system("sudo %swww/xsftp/webui/privexec.py --setlogperm > /dev/null 2>&1" % xsftp.common.constants.APPDIR)
    # check that the file passed in the URL is something expected.
    logFiles = [ logFile.split("/")[-1] for logFile in glob.glob(xsftp.webui.constants.SYSLOG_LOG_FILE + "*")]
    if filename not in logFiles:
        putMessage(request, "Error: No such log file named '%s'." % filename, CRITICAL)
        return HttpResponseRedirect('/systemlog/')
    source_file = "/".join(xsftp.webui.constants.SYSLOG_LOG_FILE.split("/")[:-1] + [filename])
    # putMessage(request, "source file is: %s" % source_file, DEBUG)
    f = file(source_file, 'r')
    content = f.read()
    f.close()
    response = HttpResponse()
    response.content = content
    response["Content-Disposition"] = "attachment; filename=%s" % filename
    log("user '%s' has downloaded Archived System Log: %s" % (request.user.username, filename))
    return response


# **************************************
#         Subscription Views
# **************************************

@valid_user
@admin_required
def subscriptions(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("Subscriptions", "/subscriptions/"))
    license_list = LICENSE.get_licenses()
    total_licenses = len(license_list)
    # define leet table headings
    headings = []
    LeetHeading = xsftp.webui.forms.LeetHeading
    headings.append((LeetHeading("Subscription Type"), "type"))
    headings.append((LeetHeading("Description"), "description"))
    headings.append((LeetHeading("Quantity"), "quantity"))
    headings.append((LeetHeading("Purchase Date"), "purchase_date"))
    headings.append((LeetHeading("Expiry"), "expiry"))
    headings.append((LeetHeading("Days Remaining"), "days_remaining"))
    # Filter the results
    filter = ""
    if "filter" in request.GET.keys():
        filter = request.GET["filter"]
        license_list = [license for license in license_list if    filter in license.type or\
                                                                filter in license.description or\
                                                                filter in str(license.quantity) or\
                                                                filter in license.get_purchase_date() or\
                                                                filter in license.get_expiry() or\
                                                                filter in str(license.get_days_remaining())]
    # sort the table
    sortOrder = "asc"
    sortCol = "type"
    if "sortCol" in request.GET.keys():
        passed_sortCol = request.GET["sortCol"]
        if passed_sortCol in [h[1] for h in headings]:
            sortCol = passed_sortCol
    if "sortOrder" in request.GET.keys():
        sortOrder = request.GET["sortOrder"]
    if sortOrder == "desc":
        license_list.sort(cmp=lambda x,y: cmp(y.__getattribute__(sortCol), x.__getattribute__(sortCol)))
        sortCol = "-%s" % sortCol
    else:
        license_list.sort(cmp=lambda x,y: cmp(x.__getattribute__(sortCol), y.__getattribute__(sortCol)))
    # create the leettable
    final_license_list = []
    for l in license_list:
        line_colour = "black"
        days_remaining = l.get_days_remaining()
        if days_remaining == None:
            days_remaining = "Unlimited"
        if type(days_remaining) == type(int()):
            if days_remaining < 15:
                line_colour = "#FF6600"
            if days_remaining < 1:
                line_colour = "red"
                days_remaining = "Expired!"
        final_license_list.append(((l.type, l.description, str(l.quantity), l.get_purchase_date(), l.get_expiry(), days_remaining), line_colour))
    the_table = xsftp.webui.forms.LeetTable(action="/subscriptions/", headings=headings, objects=final_license_list, filterable=True, sortable=True, buttons=[], filter=filter, totalObjects=total_licenses, sortCol=sortCol, sortOrder=sortOrder, objectDescription="Subscription")
    # generate subscription summart stats
    summary_ltypes = ["USER", "SERVERLINK", "JOB"] #FIXME add the other subscription types to the suymmary, dont hard code this here ffs
    summary = []
    for ltype in LICENSE.subscribed_types():
        if not ltype in summary_ltypes: continue
        ltype_max = LICENSE.get_active_license_count(ltype)
        if ltype == "USER":
            ltype_used = xsftp.webui.models.User.objects.count()
        elif ltype == "SERVERLINK":
            ltype_used = xsftp.webui.models.Server.objects.count()
        elif ltype == "JOB":
            ltype_used = xsftp.webui.models.Job.objects.count()
        ltype_remaining = ltype_max - ltype_used
        if ltype_remaining < 0:
            ltype_remaining = "%s (A subscription renewal is required to re-activate excess %ss!)" % (ltype_remaining, ltype.lower())
        summary.append((ltype, ltype_max, ltype_used, ltype_remaining))
    params = {'title':'%s Subscriptions' % TITLE,
        'pageid':'subscriptions',
        'leet_table':the_table,
        'license':LICENSE,
        'summary':summary,
        }
    return render_response('subscriptions.html', request, params)


###################################################
#             Operator Views
###################################################


# **************************************
#         My Server Views
# **************************************


@valid_user
def myserverlinks(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("My Server Links", "/myserverlinks/"))
    if not is_daemon_running():
        putMessage(request, "The Fcombine service is not running, Server Link health data may be inaccurate. Contact your Fcombine system administrator for assistance.", WARNING)
    headings = []
    LeetHeading = xsftp.webui.forms.LeetHeading # could import it specifically, but this should work too
    headings.append((LeetHeading("Server Link Name", render_as="link"), "server_name"))
    headings.append((LeetHeading("Permission", sortable=False), ""))
    headings.append((LeetHeading("Address"), "address"))
    headings.append((LeetHeading("Type"), "type"))
    headings.append((LeetHeading("Enabled", render_as="boolean"), "enabled"))
    headings.append((LeetHeading("Status", render_as="null_boolean"), "status"))
    headings.append((LeetHeading("Comment"), "comment"))
    # Build the query object
    filter = ""
    if "filter" in request.GET.keys():
        filter = request.GET["filter"]
        q_object =     Q(server_name__icontains=filter) |\
                    Q(address__icontains=filter) |\
                    Q(enabled__icontains=filter) |\
                    Q(status__icontains=filter) |\
                    Q(type__icontains=filter) |\
                    Q(comment__icontains=filter)
        servers = xsftp.webui.models.Server.objects.filter(q_object)
    else:
        servers = xsftp.webui.models.Server.objects.all()
    # Now sort the servers based on the appropriate column
    # First, set sortOrder and sortCol to sensible defaults
    sortOrder = "asc"
    sortCol = "server_name"
    # Then overwrite them if they have been specified
    if "sortCol" in request.GET.keys():
        passed_sortCol = request.GET["sortCol"]
        if passed_sortCol in [h[1] for h in headings]:
            sortCol = passed_sortCol
    if "sortOrder" in request.GET.keys():
        sortOrder = request.GET["sortOrder"]
    if sortOrder == "desc":
        sortCol = "-%s" % sortCol
    servers = servers.order_by(sortCol)
    # Now build a list of the server link attribute tuples to put in the leet table
    serverList = odict()
    for server in servers:
        if request.user in server.getAllReadUsers():
            # calculate this user's effective permission on this server
            if request.user in server.getEffectiveWriteUsers():
                effectivePermission = "Read/Write"
            else:
                effectivePermission = "Read Only"
            type = server.type.upper()
            if server.type == "ftp":
                if server.ftp_ssl:
                    type = "FTPES"
                    if server.ftp_ssl_implicit:
                        type = "FTPS"
            if not server.enabled:
                status = None
            else:
                status = server.status == 0
            serverList[server.id] = ((server.server_name, "/myserverlinks/view/%s/" % server.id), effectivePermission, server.address, type, server.enabled, status, server.comment)
    totalServers = len(request.user.userprofile.getAllReadServers())
    the_table = xsftp.webui.forms.LeetTable(action="/myserverlinks/", headings=headings, objects=serverList.values(), filterable=True, sortable=True, filter=filter, totalObjects=totalServers, sortCol=sortCol, sortOrder=sortOrder, objectDescription="Server Link")
    params = {'title':'%s My Server Links' % TITLE,
        'pageid':'myserverlinks',
        'leet_table':the_table,
        }
    return render_response('myserverlinks.html', request, params)


@valid_user
def viewmyserverlink(request, serverid):
    server = xsftp.webui.models.Server.objects.get(id = serverid)
    pushBreadCrumb(request, ("View My Server Link '%s'" % server.server_name, "/myserverlinks/view/%s/" % serverid))
    if not is_daemon_running():
        putMessage(request, "The Fcombine service is not running, Server Link health data may be inaccurate. Contact your Fcombine system administrator for assistance.", WARNING)
    # ensure user has permission to view this server
    if request.user not in server.getAllReadUsers():
        putMessage(request, "You do not have permission to view server '%s'" % server.server_name, CRITICAL)
        if request.META.has_key("HTTP_REFERER"):
            redirect = request.META["HTTP_REFERER"]
        else:
            redirect = "/jobs/"
        return HttpResponseRedirect(redirect)
    if request.user in server.getEffectiveWriteUsers():
        effectivePermission = "Read/Write"
    else:
        effectivePermission = "Read Only"
    params = {'title':'%s My Server Links' % TITLE,
        'pageid':'myserverlinks',
        'server_to_view':server,
        'effectivePermission':effectivePermission,
        }
    return render_response('viewmyserver.html', request, params)


# **************************************
#         My Script Views
# **************************************

@valid_user
def myscripts(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("My Scripts", "/myscripts/"))
    headings = []
    LeetHeading = xsftp.webui.forms.LeetHeading # could import it specifically, but this should work too
    headings.append((LeetHeading("Script Name"), "script_name"))
    headings.append((LeetHeading("File"), "file"))
    headings.append((LeetHeading("Comment"), "comment"))
    # Build the query object
    filter = ""
    if "filter" in request.GET.keys():
        filter = request.GET["filter"]
        q_object =  Q(script_name__icontains=filter) |\
                    Q(file__icontains=filter) |\
                    Q(comment__icontains=filter)
        scripts = xsftp.webui.models.Script.objects.filter(q_object)
    else:
        scripts = xsftp.webui.models.Script.objects.all()
    # Now sort the scripts based on the appropriate column
    # First, set sortOrder and sortCol to sensible defaults
    sortOrder = "asc"
    sortCol = "script_name"
    # Then overwrite them if they have been specified
    if "sortCol" in request.GET.keys():
        passed_sortCol = request.GET["sortCol"]
        if passed_sortCol in [h[1] for h in headings]:
            sortCol = passed_sortCol
    if "sortOrder" in request.GET.keys():
        sortOrder = request.GET["sortOrder"]
    if sortOrder == "desc":
        sortCol = "-%s" % sortCol
    scripts = scripts.order_by(sortCol)
    scriptList = odict()
    for script in scripts:
        if request.user in script.getEffectiveUsers():
            scriptList[script.id] = (script.script_name, script.file, script.comment)
    totalScripts = len(request.user.userprofile.getEffectiveScripts())
    the_table = xsftp.webui.forms.LeetTable(action="/myscripts/", headings=headings, objects=scriptList.values(), filterable=True, sortable=True, filter=filter, totalObjects=totalScripts, sortCol=sortCol, sortOrder=sortOrder, objectDescription="Script")
    params = {'title':'%s My Scripts' % TITLE,
        'pageid':'myscripts',
        'leet_table':the_table,
        }
    return render_response('myscripts.html', request, params)


@valid_user
def viewmyscript(request, scriptid):
    script = xsftp.webui.models.Script.objects.get(id = scriptid)
    pushBreadCrumb(request, ("View My Script '%s'" % script.script_name, "/myscripts/view/%s/" % scriptid))
    # ensure user has permission to view this script
    if request.user not in script.getEffectiveUsers():
        putMessage(request, "You do not have permission to view script '%s'" % script.script_name, CRITICAL)
        if request.META.has_key("HTTP_REFERER"):
            redirect = request.META["HTTP_REFERER"]
        else:
            redirect = "/myscripts/"
        return HttpResponseRedirect(redirect)
    params = {'title':'%s View My Script' % TITLE,
        'pageid':'myscripts',
        'script_to_view':script,
        }
    return render_response('viewmyscript.html', request, params)


# **************************************
#         My Profile Views
# **************************************


@valid_user
def myprofile(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("Profile", "/myprofile/"))
    user = request.user
    users_groups = user.xgroup_set.all()
    users_scripts = user.userprofile.getEffectiveScripts()
    users_read_servers = [s for s in user.userprofile.getEffectiveReadServers() if s.enabled]
    users_write_servers = [s for s in user.userprofile.getEffectiveWriteServers() if s.enabled]
    params = {'title':'%s My Profile' % TITLE,
        'pageid':'myprofile',
        'user_to_view':user,
        'users_groups':users_groups,
        'users_scripts':users_scripts,
        'users_read_servers':users_read_servers,
        'users_write_servers':users_write_servers,
        "userprofile_to_view": user.userprofile,
        }
    return render_response('myprofile.html', request, params)


@valid_user
def editprofile(request): #XXX unused in current release - only admins should be able to edit users full name and email address (manually or via central user management/sync system)
    # get user and user_profile objects specified in userid arg
    user = request.user
    pushBreadCrumb(request, ("Edit Profile", "/myprofile/edit/"))
    # check if they just came to this form via clicking "Edit User", or are actually submitting some modifications
    profile_attributes = request.POST.copy()
    if request.POST:
        # they are submitting some modifications, validate them.
        # if "Cancel" button was pressed
        if "button" in request.POST.keys() and request.POST["button"] == "Cancel":
            # return to previous page
            popBreadCrumb(request)
            putMessage(request, "Cancelled profile modification", WARNING)
            return HttpResponseRedirect("/myprofile/")
        # populate and validate the form
        if is_demo_user(request): return demo_user_block(request)
        edit_profile_form = xsftp.webui.forms.EditProfileForm(request.POST)
        if edit_profile_form.is_valid():
            edit_profile_form.save()
            popBreadCrumb(request)
            putMessage(request, "Successfully modified your profile")
            log("user '%s' has modified their Profile" % request.user.username)
            return HttpResponseRedirect("/myprofile/")
        else:
            # form was invalid
            putMessage(request, "Please correct the errors below.", CRITICAL)
    else:
        profile_attibutes = dict()
        profile_attributes["user_id"] = user.id
        profile_attributes["first_name"] = user.first_name
        profile_attributes["last_name"] = user.last_name
        profile_attributes["email"]    = user.email
    # instantiate the form
    edit_profile_form = xsftp.webui.forms.EditProfileForm(profile_attributes)
    params = {"title":'%s Edit User' % TITLE,
        'pageid':'myprofile',
        "edit_profile_form":edit_profile_form,
        }
    return render_response("editprofile.html", request, params)


@valid_user
def changemypass(request):
    if not request.user.userprofile.internal_auth:
        putMessage(request, "Your password can only be changed via your external user management system.", CRITICAL)
        return HttpResponseRedirect(request.META["HTTP_REFERER"])
    pushBreadCrumb(request, ("Change My Password", "/changemypass/"))
    if request.method == "POST":
        if request.POST["button"] != "Apply":
            putMessage(request, "Cancelled password change", WARNING)
            if "breadCrumbs" in request.session.keys() and len(request.session["breadCrumbs"]) > 1:
                popBreadCrumb(request)
                return HttpResponseRedirect(request.session["breadCrumbs"][-1][1])
            else:
                return HttpResponseRedirect("/")
        if is_demo_user(request): return demo_user_block(request)
        changemypassform = xsftp.webui.forms.ChangeMyPasswordForm(request.user, request.POST)
        if not changemypassform.is_valid():
            putMessage(request, "Please correct the errors below." , CRITICAL)
            # we need to clear the password, but we are not allowed to modify the immutable QueryDict named Data
            # Instaed, we make a copy, and then re-attach the copy to the form in place of the original
            newData = changemypassform.data.copy()
            newData["old_password"] = u''
            newData["new_password_1"] = u''
            newData["new_password_2"] = u''
            changemypassform.data = newData
        else:
            request.user.set_password(request.POST["new_password_1"])
            request.user.save()
            # set users password in linux
            setLinuxPassword(request.user.username, request.POST["new_password_1"])
            log("user '%s' changed their password" % request.user.username)
            putMessage(request, "Password Change Successful!", INFO)
            if "breadCrumbs" in request.session.keys() and len(request.session["breadCrumbs"]) > 1:
                popBreadCrumb(request)
                return HttpResponseRedirect(request.session["breadCrumbs"][-1][1])
            else:
                return HttpResponseRedirect("/")
    else:
        changemypassform = xsftp.webui.forms.ChangeMyPasswordForm(request.user)
    params = {'title':'%s Change My Password' % TITLE,
        'pageid':'changemypass',
        'myform':changemypassform,
        }
    return render_response('changemypass.html', request, params)



# **************************************
#         My SSH Keys Views
# **************************************


@valid_user
def mysshkeys(request):
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("My SSH Keys", "/mysshkeys/"))
    # get the public keys from the user's authorized_keys file
    try:
        ssh_keys_tmp = xsftp.webui.forms.read_authorized_keys(request.user.username)
    except Exception, e:
        error_desc = e[0]
        line_number = e[1]
        putMessage(request, "Error reading authorized_keys at line %s: '%s'. Please contact your Fcombine administrator." % (line_number, error_desc), CRITICAL)
        return HttpResponseRedirect("/login/")
    # create a __unicode__() method for each key object so that the template can render their names
    ssh_keys = []
    for key in ssh_keys_tmp:
        key.__unicode__ = new.instancemethod(lambda obj: "%s (Fingerprint: %s)" % (obj.comment, obj.fingerprint), key, key.__class__)
        ssh_keys.append(key)
    # If there exist submit values are in the GET paramaters, handle them
    if "button" in request.GET.keys():
        if request.GET["button"] == "Delete":
            if request.GET.getlist("selected"):
                # call the confirmation view - give it the verb, the nouns, and a description of the nouns
                selected_ssh_keys = [key for key in ssh_keys if unicode(key.id) in request.GET.getlist("selected")]
                return confirm_action(request, action=request.GET["button"], objects=selected_ssh_keys, description="SSH Public Key", processor="/mysshkeys/")
            else:
                putMessage(request, "You didn't select any SSH Public Keys to %s" % request.GET["button"].lower(), WARNING)
    # define leet table headings
    headings = []
    LeetHeading = xsftp.webui.forms.LeetHeading
    headings.append((LeetHeading("_select_all", render_as="checkbox", sortable=False), "id"))
    headings.append((LeetHeading("Name (Comment)", render_as="link"), "comment"))
    headings.append((LeetHeading("SSH-2 Key Type"), "str_type"))
    headings.append((LeetHeading("Bit Length"), "bit_length"))
    headings.append((LeetHeading("Fingerprint"), "fingerprint"))
    # Filter the results
    filter = ""
    total_keys = len(ssh_keys)
    if "filter" in request.GET.keys():
        filter = request.GET["filter"]
        ssh_keys = [key for key in ssh_keys if    filter in key.comment or\
                                                filter in key.str_type or\
                                                filter in str(key.bit_length) or\
                                                filter in key.fingerprint]
    # Now sort the scripts based on the appropriate column
    sortOrder = "asc"
    sortCol = "comment"
    if "sortCol" in request.GET.keys():
        passed_sortCol = request.GET["sortCol"]
        if passed_sortCol in [h[1] for h in headings]:
            sortCol = passed_sortCol
    if "sortOrder" in request.GET.keys():
        sortOrder = request.GET["sortOrder"]
    if sortOrder == "desc":
        ssh_keys.sort(cmp=lambda x,y: cmp(y.__getattribute__(sortCol), x.__getattribute__(sortCol)))
        sortCol = "-%s" % sortCol
    else:
        ssh_keys.sort(cmp=lambda x,y: cmp(x.__getattribute__(sortCol), y.__getattribute__(sortCol)))
    ssh_key_list = odict()
    for key in ssh_keys:
        if unicode(key.id) in request.GET.getlist("selected"):
            selected = 1
        else:
            selected = 0
        ssh_key_list[key.id] = ((key.id, selected), (key.comment, "/mysshkeys/edit/%s/" % key.id), key.str_type, key.bit_length, key.fingerprint)
    # create the buttons
    button_list = []
    button_list.append(xsftp.webui.forms.LeetButton(value="Delete"))
    # create the leettable
    the_table = xsftp.webui.forms.LeetTable(action="/mysshkeys/", headings=headings, objects=ssh_key_list.values(), filterable=True, sortable=True, buttons=button_list, filter=filter, totalObjects=total_keys, sortCol=sortCol, sortOrder=sortOrder, objectDescription="SSH Key")
    params = {'title':'%s My SSH Keys' % TITLE,
        'pageid':'mysshkeys',
        'leet_table':the_table,
        }
    return render_response('mysshkeys.html', request, params)


@valid_user
def domodifymysshkeys(request, action):
    # Check if the user has the priveleges to modify each script
    if request.POST["button"] != "Yes":
        putMessage(request, "%s cancelled" % action.title(), WARNING)
        return HttpResponseRedirect("/mysshkeys/")
    if is_demo_user(request): return demo_user_block(request)
    if action == "delete":
        keys_fingerprints_to_delete = [(key.fingerprint, key.comment) for key in xsftp.webui.forms.read_authorized_keys(request.user.username) if str(key.id) in request.POST.getlist("selected")]
        log_messages = []
        for fingerprint, comment in keys_fingerprints_to_delete:
            delKeysCmd = "sudo %swww/xsftp/webui/privexec.py --del_public_key=%s %s  > /dev/null 2>&1" % (xsftp.common.constants.APPDIR, request.user.username, fingerprint)
            os.system(delKeysCmd)
            line = "%s (Fingerprint: %s)" % (comment, fingerprint)
            log_messages.append(line)
        log_messages = ", ".join(log_messages)
        putMessage(request, "SSH Public Keys deleted: %s" % log_messages, INFO)
        log("user '%s' has deleted SSH Public Keys: %s" % (request.user.username, log_messages))
    else:
        putMessage(request, "Unknown action provided - no action was taken", WARNING)
    return  HttpResponseRedirect("/mysshkeys/")


@valid_user
def importsshkeys(request):
    pushBreadCrumb(request, ("Import SSH Key", "/mysshkeys/import/"))
    from xsftp.webui.upload_handler import Max_Size_Upload_Handler
    upload_handler = Max_Size_Upload_Handler(1024*1024*2)
    request.upload_handlers.insert(0, upload_handler)
    importsshkeyform = xsftp.webui.forms.importSshKeyForm()
    if request.method == 'POST':
        if is_demo_user(request): return demo_user_block(request)
        importsshkeyform = xsftp.webui.forms.importSshKeyForm(request.POST, request.FILES)
        if importsshkeyform.is_valid():
            try:
                filename, duplicates = importsshkeyform.save(request.user.username)
            except Exception, e:
                putMessage(request, "Failed to import SSH Public Key(s) from specified file. Error: %s" % e, CRITICAL)
                return HttpResponseRedirect("/mysshkeys/")
            if not duplicates:
                putMessage(request, "Successfully imported SSH Public Key(s).", INFO)
            else:
                dup_messages = []
                for key in duplicates:
                    message = "%s (fingerprint: %s)" % (key.comment, key.fingerprint)
                    dup_messages.append(message)
                putMessage(request, "Imported SSH Public Key(s) but skipped the following duplicates: %s" % ", ".join(dup_messages), INFO)
            log("user '%s' has imported SSH Public key(s) from file: %s" % (request.user.username, filename))
            return HttpResponseRedirect("/mysshkeys/")
        else:
            if upload_handler.message:
                putMessage(request, upload_handler.message, CRITICAL)
                return HttpResponseRedirect("/mysshkeys/")
            putMessage(request, "Please correct the errors below.", CRITICAL)
    params = {'title':'%s Import SSH Pubkic Keys' % TITLE,
        'pageid':'mysshkeys',
        'importsshkeyform':importsshkeyform,
        }
    return render_response("importsshkeys.html", request, params)


@valid_user
def editsshkey(request, key_id):
    key = ([key for key in xsftp.webui.forms.read_authorized_keys(request.user.username) if str(key.id) == key_id] + [None])[0]
    if not key:
        putMessage(request, "Error: Could not locate the specified key.", CRITICAL)
        return HttpResponseRedirect("/mysshkeys/")
    pushBreadCrumb(request, ("Edit SSH Key", "/mysshkeys/edit/%s/" % key_id))
    # generate base64 data for template
    base64lines = []
    base64data = key.get_base64()
    while base64data:
        base64lines.append(base64data[:64])
        base64data = base64data[64:]
    # do the form stuff
    if request.method == "POST":
        if request.POST["button"] == "Cancel":
            popBreadCrumb(request)
            putMessage(request, "Canceled SSH Key modification", WARNING)
            return HttpResponseRedirect("/mysshkeys/")
        # They are trying to submit data to modify the key
        if is_demo_user(request): return demo_user_block(request)
        edit_ssh_key_form = xsftp.webui.forms.EditSshKeyForm(request.POST)
        if edit_ssh_key_form.is_valid():
            message = edit_ssh_key_form.save(request.user.username)
            popBreadCrumb(request)
            if not message:
                putMessage(request, "Successfully modified SSH Key: %s" % key.fingerprint, INFO)
            else:
                putMessage(request, message, WARNING)
            log("user '%s' has modified key: %s" % (request.user.username, key.fingerprint))
            return HttpResponseRedirect('/mysshkeys/')
        else:
            # form was invalid
            putMessage(request, "Please correct the errors below.", CRITICAL)
    else:
        form_data = {'fingerprint':key.fingerprint, 'key_name':[key.comment, ""][key.comment == "(none specified)"]}
        edit_ssh_key_form = xsftp.webui.forms.EditSshKeyForm(form_data)
    params = {'title':'%s Edit SSH key' % TITLE,
        'pageid':'mysshkeys',
        'key_to_edit':key,
        'base64lines':base64lines,
        'edit_ssh_key_form': edit_ssh_key_form,
        }
    return render_response('editsshkey.html', request, params)



# **************************************
#         File Explorer Views
# **************************************


def cleanPath(path):
    '''
    Cleans up any "." and/or ".." entries in specified path, and returns result.
    - Does *not* evaluate or resolve symlinks.
    '''
    pathParts = path.split("/")
    newParts = list()
    for part in pathParts:
        if part == '..' and newParts:
            newParts.pop()
        if part == "":
            newParts.append("/")
        elif part != '..' and part != '.':
            newParts.append(part)
    if newParts:
        newPath = os.path.join(*newParts)
    else:
        newPath = "/"
    return newPath


def vroot(pathArg, homeDir, request):
    '''
    Turns a relative path (from the user's point of view) into an absolute path on the device, thereby vrooting it.
    '''
    jailDir = homeDir + 'xsftp/'
    # resolve the absolute path of pathArg, relative to the *real* root directory:
    symlinkCount = 0
    while True:
        # remove .'s and ..'s from specified pathArg
        pathArg = cleanPath(pathArg)
        #putMessage(request, "cleaned path is: %s" % pathArg, DEBUG)
        # iterate through pathArg's parts to find symlinks which we need to resolve.
        pathArgParts = pathArg.split("/")
        foundSymlink = False
        for index in range(len(pathArgParts)):
            partsSoFar = pathArgParts[:index+1]
            partsRemaining = pathArgParts[index+1:]
            #putMessage(request, "working on: %s\t\tremaining: %s" % (partsSoFar, partsRemaining), DEBUG)
            # assemble the real path of "partsSoFar" (relative to real root) for symlink testing.
            testPath = os.path.join(jailDir, *partsSoFar)
            # check if it's a symlink
            if os.path.islink(testPath):
                foundSymlink = True
                # ensure it hasn't exceeded the MAXSYMLINKS (20) limit.
                symlinkCount += 1
                if symlinkCount > 20:
                    #FIXME print "cannot access '%s': Too many levels of symbolic links" % pathArg
                    return ""
                # get the symlink's value
                linkTarget = os.readlink(testPath)
                # if symlink value is absolute
                if linkTarget.startswith("/"):
                    #putMessage(request, "Found an absolute symlink at '%s'!" % testPath, DEBUG)
                    # change pathArg to symlinkValue + partsRemaining (thus stripping off partsSoFar) and restart the whole loop
                    pathArg = os.path.join(linkTarget, *partsRemaining)
                    #putMessage(request, "modifying pathArg to '%s' and re-checking..." % pathArg, DEBUG)
                    break
                # else, symlink value is relative
                else:
                    #putMessage(request, "Found a relative symlink at '%s'!" % testPath, DEBUG)
                    # just replace the symlink in pathArg with its value, and restart the whole loop
                    newParts = partsSoFar[:-1] + linkTarget.split("/") + partsRemaining
                    pathArg = os.path.join(*newParts)
                    #putMessage(request, "modifying pathArg to '%s' and re-checking..." % pathArg, DEBUG)
                    break
        if not foundSymlink:
            # If we get here, testPath contains our final result.
            #putMessage(request, "evaluated the real jail dir to be: %s" % testPath, DEBUG)
            break
    return testPath


class ClipboardItem(object):
    '''
    Simple class representing an item on the File Explorer's clipboard.
    '''
    def __init__(self, name, curr_dir, type=None):
        if not type:
            self.type, self.name = name.split('_', 1)
        else:
            self.name = name
            self.type = type
        # prepend the curr_dir to the clipboard item base name, paying attention to the joining "/" character if required
        name_prefix = curr_dir
        if not curr_dir == "/":
            name_prefix += "/"
        self.name = name_prefix + self.name

    def __str__(self):
        return self.name

    def __repr__(self):
        return self.__str__()

@valid_user
def explorer(request):
    # setup some variables
    clearBreadCrumbs(request)
    pushBreadCrumb(request, ("File Explorer", "/explorer/"))
    writeable = False
    at_root = False # flag used to determine whether to add ".." to list of dirs
    home_dir = "/home/%s/" % request.user.username
    curr_dir = "/" # placeholder - will get overwritten with untrusted data
    real_dir = vroot(curr_dir, home_dir, request) # real_dir is now hard_coded-ish to the jail directory, relative to the appliance

    # If they posted something, then yay
    if request.POST:
        # There are many operations that they can perform. They are all mutually exclusive, I think
        # Operations are: chdir, delete, rename, tag, clear_tag, copy, move, mkdir, upload
        operation = request.POST.has_key("operation") and request.POST["operation"]
        curr_dir = request.POST.has_key("curr_dir") and request.POST["curr_dir"] or "/"
        if curr_dir == "/":
            at_root = True
        else:
            at_root = False
        real_dir = vroot(curr_dir, home_dir, request)

        # handle each operation that the user may perform
        if operation == "chdir":
            curr_dir = cleanPath(os.path.join(curr_dir, request.POST["new_dir"]))
            real_dir = vroot(curr_dir, home_dir, request)
            if curr_dir == "/":
                at_root = True
            else:
                at_root = False

        elif operation == "delete":
            if request.POST.has_key("lhs_selected"):
                items = request.POST.getlist("lhs_selected")
                # Strip off the 'type' prefix of each name
                items = [item.split("_", 1)[1] for item in items]
                #putMessage(request, items, DEBUG)
                for item in items:
                    item = "%s%s" % (["%s/" % curr_dir, curr_dir][at_root], item)
                    item = vroot(item, home_dir, request)
                    # Check that item in user's xsftp dir
                    # Check that item exists
                    # Clean up any path parts (eg ".", ".." etc)
                    privexec_args = ["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--explorer_delete", item]
                    p = subprocess.Popen(privexec_args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                    stdout, stderr = p.communicate()
                    if stdout or stderr:
                        try:
                            error = pickle.loads(stdout)
                            putMessage(request, error, CRITICAL)
                        except Exception, e:
                            putMessage(request, stdout, CRITICAL)
                            putMessage(request, stderr, CRITICAL)

        elif operation == "rename":
            # FIXME hi mum!
            pass

        elif operation == "add": # "tag" in the gui
            if not request.session.has_key("clipboard_items"):
                request.session["clipboard_items"] = list()
            if request.POST.has_key("lhs_selected"):
                tagged_items = [ClipboardItem(item, curr_dir) for item in request.POST.getlist("lhs_selected")]
                for item in tagged_items:
                    putMessage(request, "%s: %s" % (item.type, item.name), DEBUG)
                for item in tagged_items:
                    if not item.name in [cb_item.name for cb_item in request.session["clipboard_items"]]:
                        request.session["clipboard_items"].append(item)
                request.session["clipboard_items"].sort(cmp=lambda x,y: cmp(x.name, y.name))

        elif operation == "clear":
            if request.session.has_key("clipboard_items") and request.POST.has_key("rhs_selected"):
                clipboard_items = request.session["clipboard_items"][:]
                for item in clipboard_items:
                    if item.name in request.POST.getlist("rhs_selected"):
                        request.session["clipboard_items"].remove(item)
                del clipboard_items

        elif operation == "copy":
            # check if Dest dir is writable as far as we know
            sources = request.POST.has_key("rhs_selected") and request.POST.getlist("rhs_selected") or []
            errors = []
            overwrites = []
            successes = []
            for source in sources:
                orig_source = source
                abs_source = vroot(source, home_dir, request)
                # Check that source exists
                # Clean up any path parts (eg ".", ".." etc)
                # Check that source and dest are not the same
                privexec_args = ["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--explorer_copy",  abs_source, real_dir] # real_dir is the destination, in absolute terms on the appliance
                p = subprocess.Popen(privexec_args, stdout=subprocess.PIPE)
                stdout, stderr = p.communicate()
                if stdout:
                    error = pickle.loads(stdout)
                    if len(error.message) == 2: # do_copy() in privexec.py may raise an Exception with a 2-tuple argument in form (status, message)
                        status = error.message[0]
                        message = error.message[1]
                        if status == 400:
                            overwrites.append(orig_source)
                        else:
                            errors.append((orig_source, error))
                    else:
                        errors.append((orig_source, error))
                else: # No stdout, so it must have been successful
                    successes.append(orig_source)
            if successes:
                putMessage(request, "The following files and/or directories were successfully copied: %s" % ", ".join(successes), INFO)
            if errors:
                putMessage(request, "The following files were not copied:\n %s" % "\n".join(["%s: %s" % (e[0], e[1].message) for e in errors]), CRITICAL)
            # clean success out of the clipboard
            for item in request.session["clipboard_items"][:]:
                if item.name in successes:
                    request.session["clipboard_items"].remove(item)
            if overwrites:
                # build context
                params = {'title': '%s File Explorer - Confirm Overwrite' % TITLE,
                    'pageid': 'explorer',
                    'curr_dir': curr_dir,
                    'objects': overwrites,
                    'action_description': "overwrite",
                    'description': "files and/or directories",
                    'processor': '/explorer/',
                    'operation': 'force_copy',
                    }
                return render_response('explorer_confirm.html', request, params)

        elif operation == "force_copy":
            if (request.POST.has_key("button") and request.POST["button"] == "Yes"):
                errors = []
                successes = []
                for source in request.POST.getlist("selected"):
                    dest_file_to_be_overwritten = os.path.join(real_dir, os.path.basename(source))
                    source_abs_path = vroot(source, home_dir, request)
                    privexec_args = ["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--explorer_temporary_rename",  dest_file_to_be_overwritten]
                    p = subprocess.Popen(privexec_args, stdout=subprocess.PIPE)
                    stdout, stderr = p.communicate()
                    response = pickle.loads(stdout)
                    if isinstance(response, Exception):
                        errors.append((source, "Could not temporarily rename the conflicting destination file '%s': %s" % (os.path.basename(source), response.message)))
                        continue
                    # if we got back something that was not an exception, then success! We must have gotten an (200, <new_temp_filename>)
                    temp_name = response[1]
                    # Copy the orig source to the dest_dir
                    privexec_args = ["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--explorer_copy",  source_abs_path, real_dir]
                    p = subprocess.Popen(privexec_args, stdout=subprocess.PIPE)
                    stdout, stderr = p.communicate()
                    # If that fails:
                    if stdout:
                        # add this source to errors
                        error = pickle.loads(stdout)
                        errors.append((source, "Could not copy file '%s': %s" % (source, error.message)))
                        # clean up by renaming the temp-renamed source to its original name
                        privexec_args = ["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--explorer_move",  os.path.join(real_dir, temp_name), dest_file_to_be_overwritten]
                        p = subprocess.Popen(privexec_args, stdout=subprocess.PIPE)
                        stdout, stderr = p.communicate()
                        if stdout:
                            error = pickle.loads(stdout)
                            errors.append((source, "Additionally, the original file was temporarily renamed to '%s', but could not be renamed back to its original name of '%s': %s" % (temp_name, os.path.basename(source), error.message)))
                        continue
                    # Delete the temp-renamed source
                    privexec_args = ["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--explorer_delete",  os.path.join(real_dir, temp_name)]
                    p = subprocess.Popen(privexec_args, stdout=subprocess.PIPE)
                    stdout, stderr = p.communicate()
                    # If this fails:
                    if stdout:
                        error = pickle.loads(stdout)
                        errors.append((source, "The source file was successfully copied, however the conflicting destination file that was to be overwritten was temporarily renamed to '%s', but now cannot be deleted: %s" % (temp_name, error.message)))
                        continue
                    # any source that was successfully copied we now delete from the clipboard
                    for item in request.session["clipboard_items"][:]:
                        if item.name == source:
                            request.session["clipboard_items"].remove(item)
                    successes.append(source)
                if successes:
                    putMessage(request, "The following items were successfully copied (with overwrite): %s" % ", ".join(successes), INFO)
                if errors:
                    putMessage(request, "The following items could not be copied:\n %s" % '\n'.join(["%s: %s" % (e[0], e[1]) for e in errors]), CRITICAL)
            else:
                putMessage(request, "Overwrite of the following files has been cancelled: %s" % ", ".join(request.POST.getlist("selected")), WARNING)

        elif operation == "move":
            sources = request.POST.getlist("rhs_selected")
            putMessage(request, sources, DEBUG)
            for source in sources:
                source = vroot(source, home_dir, request)
                # Check that source and dest are in user's xsftp dir
                # check if Dest exists, ask confirmation
                # check if Dest dir is writable as far as we know
                # Check that source exists
                # Clean up any path parts (eg ".", ".." etc)
                # Check that source and dest are not the same
                privexec_args = ["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--explorer_move",  source, os.path.join(real_dir, os.path.basename(source))]
                putMessage(request, privexec_args, DEBUG)
                p = subprocess.Popen(privexec_args, stdout=subprocess.PIPE)
                stdout, stderr = p.communicate()
                if stdout:
                    error = pickle.loads(stdout)
                    putMessage(request, error, DEBUG)

        elif operation == "mkdir":
            if request.POST.has_key("dir_name"):
                dir_name = request.POST["dir_name"]
                #putMessage(request, dir_name, DEBUG)
                privexec_args = ["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--explorer_mkdir",  dir_name, real_dir]
                p = subprocess.Popen(privexec_args, stdout=subprocess.PIPE)
                stdout, stderr = p.communicate()
                #putMessage(request, stdout, DEBUG)
                #putMessage(request, stderr, DEBUG)    
                if stdout:
                    error = pickle.loads(stdout)
                    putMessage(request, error, CRITICAL)

        elif operation == "upload":
            request.session["curr_dir"] = request.POST["curr_dir"]
            params = {'title': '%s File Explorer - Upload' % TITLE,
                'pageid': 'explorer',
                'curr_dir': curr_dir,
            }    
            return render_response('explorer_upload.html', request, params)

        elif operation == "getfile":
            filename = request.POST.get("filename")
            full_path_to_file = os.path.join(real_dir, filename)
            privexec_args = ["sudo", "%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, "--explorer_getfile",  str(full_path_to_file)]
            p = subprocess.Popen(privexec_args, stdout=subprocess.PIPE)
            # FIXME develop a pre file data protocol or something
            status = p.stdout.readline()
            if status[:3] == "200":
                try:
                    file_size = int(status[4:-1])
                except ValueError, e:
                    putMessage(request, "Protocol error - got file size as '%s'" % status[4:-1], DEBUG)
                finally:
                    file_iterator = FileWrapper(p.stdout)    
                    response = HttpResponse(file_iterator)
                    response["Content-Disposition"] = "attachment; filename=%s" % filename
                    response["Content-Type"] = "text/plain"
                    response["Content-Length"] = str(file_size)
                    return response
            else:
                pass
                putMessage(request, "Got something that wasn't a 200 OK: %s" % status, DEBUG)

        else:
            # Bad operation
            putMessage(request, "Unrecognised operation", WARNING)
        slam_name = curr_dir.split("/")[1]
        if str(slam_name) in [str(s.server_name) for s in request.user.userprofile.getEffectiveWriteServers()]:
            writeable = True
    else:
        # They didn't post anything, so just display the root of their filesystem
        at_root = True

    # Now render the view based on the curr_dir, which is "/" by default unless they posted stuff and thereby altered curr_dir.
    # Get all the nodes in the real_dir
    nodes = generate_nodes(request, real_dir)
    if isinstance(nodes, Exception):
        putMessage(request, "Error reading current directory: %s" % str(nodes).replace('/home/%s/xsftp' % request.user.username, ''), CRITICAL)
        nodes = {}
    # Make the dirs and non-dirs list
    dirs = []
    non_dirs = []
    for pathname in nodes.keys():
        if isinstance(nodes[pathname], Exception):
            # privexec threw an error trying to stat this node.
            error_string = str(nodes[pathname]).replace('/home/%s/xsftp' % request.user.username, '')
            non_dirs.append((pathname, None, None, error_string))
        elif stat.S_ISDIR(nodes[pathname][0]):
            # it is a directory:
            dirs.append((pathname, None, time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(nodes[pathname][stat.ST_MTIME])), None))
        else:
            # it is not a directory
            non_dirs.append((pathname ,nodes[pathname][stat.ST_SIZE], time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(nodes[pathname][stat.ST_MTIME])), None))
    # sort the lists
    dirs.sort(cmp=lambda x,y: cmp(x[0], y[0]))
    non_dirs.sort(cmp=lambda x,y: cmp(x[0], y[0]))
    # Construct the current directory breadcrumb trail
    dir_trail = []
    path_parts = [part for part in curr_dir.split(os.sep) if part]
    for path_part in path_parts:
        path = [part[0] for part in dir_trail] + [path_part]
        parts_so_far = "/" + os.path.join(*path)
        dir_trail.append((path_part, parts_so_far))
    params = {'title': '%s File Explorer' % TITLE,
        'pageid': 'explorer',
        'curr_dir': curr_dir,
        'dir_trail': dir_trail,
        'dirs': dirs,
        'non_dirs': non_dirs,
        'writeable': writeable,
        'at_root': at_root,
        'clipboard_items': request.session["clipboard_items"]
        }
    return render_response('explorer.html', request, params)


def generate_nodes(request, directory):
    '''Returns a list of nodes in the directory
       Each node is a dictionary defining the attributes of the node'''
    read_dir_command = ('sudo', '%swww/xsftp/webui/privexec.py' % (xsftp.common.constants.APPDIR), '--readdir=%s' % (directory))
    process = subprocess.Popen(read_dir_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    (output, stderr) = process.communicate()
    try:
        nodes = pickle.loads(output)
    except Exception, e:
        return e
    return nodes


def explorer_upload(request):
    # FIXME Put javascript in the upload template to make a Cancel form submit action button to a different view. Not Here. Don't upload the file ffs. Check if it was cancelled
    # Generate realdir
    home_dir = "/home/%s/" % request.user.username
    curr_dir = request.session["curr_dir"]
    real_dir = vroot(curr_dir, home_dir, request)
    # FIXME check that the user has write privs to this location according to fcombine
    # Create a custom upload handler
    from xsftp.webui.upload_handler import Upload_Handler
    upload_handler = Upload_Handler("%swww/xsftp/webui/privexec.py" % xsftp.common.constants.APPDIR, request.user.username, real_dir)
    request.upload_handlers = [upload_handler]
    # Get all the files that got uploaded
    files = request.FILES.values()
    for message in upload_handler.messages:
        putMessage(request, message[1], [CRITICAL, INFO][message[0]])
    return explorer(request)
