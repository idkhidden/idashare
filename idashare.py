import idc
import idaapi
import ida_kernwin
import http.server
import socketserver
import threading
import os
import socket

PORT = 1337
server = None
serverthread = None

def getbinpath():
    binarypath = idc.get_input_file_path()
    if not binarypath or not os.path.exists(binarypath):
        print("[ idashare ] No valid binary loaded.")
        return None
    return binarypath

def getidbpath():
    idbpath = idc.get_idb_path()
    if not idbpath or not os.path.exists(idbpath):
        print("[ idashare ] No valid IDA database loaded.")
        return None
    return idbpath

def startserver(directory):
    global server
    os.chdir(directory)
    handler = http.server.SimpleHTTPRequestHandler
    server = socketserver.TCPServer(("0.0.0.0", PORT), handler)

    try:
        server.serve_forever()
    except Exception as e:
        print(f"[ idashare ] Server error: {e}")

def share(filepath):
    if not filepath or not os.path.exists(filepath):
        return

    dir = os.path.dirname(filepath)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(('8.8.8.8', 80))
    ip = sock.getsockname()[0]
    sock.close()
    global serverthread
    if not serverthread or not serverthread.is_alive():
        serverthread = threading.Thread(target=startserver, args=(dir,), daemon=True)
        serverthread.start()

    print(f"[ idashare ] http://{ip}:{PORT}/{os.path.basename(filepath)}")

class idashare_actionhandler(ida_kernwin.action_handler_t):
    def __init__(self, sharefunc):
        ida_kernwin.action_handler_t.__init__(self)
        self.sharefunc = sharefunc

    def activate(self, ctx):
        self.sharefunc()
        return 1

    def update(self, ctx):
        return ida_kernwin.AST_ENABLE_FOR_IDB

def register_actions():
    actionbin = ida_kernwin.action_desc_t(
        'idashare_share_bin',
        'Share binary',
        idashare_actionhandler(lambda: share(getbinpath())),
        'Ctrl+Shift+S',
        '',
        0)

    actiondb = ida_kernwin.action_desc_t(
        'idashare_share_db',
        'Share IDA database',
        idashare_actionhandler(lambda: share(getidbpath())),
        'Ctrl+Shift+D',
        '',
        0)

    ida_kernwin.register_action(actionbin)
    ida_kernwin.register_action(actiondb)

    ida_kernwin.attach_action_to_menu('Edit/idashare/', 'idashare_share_bin', ida_kernwin.SETMENU_APP)
    ida_kernwin.attach_action_to_menu('Edit/idashare/', 'idashare_share_db', ida_kernwin.SETMENU_APP)

class idashare(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = "idashare"
    help = ""
    wanted_name = "idashare"
    wanted_hotkey = ""

    def init(self):
        register_actions()
        print("[ idashare ] initialized.")
        return idaapi.PLUGIN_OK

    def run(self, arg):
        pass

    def term(self):
        print("[ idashare ] terminated.")

def PLUGIN_ENTRY():
    return idashare()
