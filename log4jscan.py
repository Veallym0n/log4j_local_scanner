import socket
import json
import zipfile
import os
import io
import glob
from urllib import request

class FatJar:

    def __init__(self, container, fileobj, filepath='',jarlevel=1):
        self.container = container
        self.jarlevel = jarlevel
        try:
            self.fileobj = zipfile.ZipFile(fileobj)
        except:
            self.fileobj = None
        self.filepath = filepath
        if jarlevel<5:
            self.scan_jar()

    def get_log4j_info(self, f, vuln_info={}):
        if f.endswith('org.apache.logging.log4j/log4j-core/pom.properties'):
            version = ([i for i in self.fileobj.open(f).read().split(b'\n') if i.startswith(b'version=')]+[b''])[0].decode()
            vuln_info['version'] = version
            vuln_info['path'] = self.filepath
        if f.endswith('JndiLookup.class'):
            vuln_info['JndiLookup.class'] = "True"
        return vuln_info

    def scan_jar(self):
        vuln = {}
        if not self.fileobj: return
        jarfile = self.fileobj
        fns = [subjar for subjar in jarfile.namelist()]
        [self.get_log4j_info(f, vuln) for f in fns]
        if vuln: self.container.append(vuln)
        [
            FatJar(self.container, io.BytesIO(jarfile.open(subjar).read()), self.filepath+'/'+subjar, self.jarlevel+1)
            for subjar in fns
            if subjar.endswith('.jar')
        ]

class RuntimeInfo:

    def __init__(self, procpath):
        self.pid = procpath.split('/',3)[2]
        self.base_info = {}
        if int(self.pid) == os.getpid(): return
        self.jar_files = [os.readlink(fd) for fd in glob.glob(procpath+'/fd/*') if os.readlink(fd).endswith('.jar')]
        if not self.jar_files: return
        self.cmdline = self.get_content('/proc/%s/cmdline' % self.pid).split('\x00')
        self.environ = self.get_content('/proc/%s/environ' % self.pid).split('\n')
        self.base_info = dict(
            pid = self.pid,
            envfix = str(any(i for i in self.environ if i=='LOG4J_FORMAT_MSG_NO_LOOKUPS=true')),
            cmdfix = str(any(i for i in self.cmdline if '-Dlog4j2.formatMsgNoLookups=true' in i)),
            jar_info = []
        )
        [FatJar(self.base_info['jar_info'], jar, jar, 1) for jar in self.jar_files]

    def get_content(self, fn):
        with open(fn) as f:
            return f.read()

def get_sys_info():
    info = {'hostname':socket.gethostname(),'private-ipv4':'127.0.0.1'}
    if os.environ.get('aliyun')=='no':
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('192.168.0.0',1))
            info['private-ipv4'] = s.getsockname()[0]
        except:
            pass
    else:
        try:
            info.update(json.loads(request.urlopen('http://100.100.100.200/latest/dynamic/instance-identity/document', timeout=0.5).read()))
        except:
            pass
    return info


def httplog(url, data=None):
    if not url.endswith('?APIVersion=0.6.0'): url+='?&APIVersion=0.6.0'
    sysinfo = get_sys_info()
    flatten_data = sum([[dict(f,envfix=i.get('envfix'),cmdfix=i.get('cmdfix'),**sysinfo) for f in i.get('jar_info')] for i in data],[])
    data_log = json.dumps({"__logs__":flatten_data}).encode()
    urlrequest = request.Request(url, data=data_log, headers={'x-log-apiversion':'0.6.0','x-log-bodyrawsize':len(data_log)})
    try:
        ff = request.urlopen(urlrequest, timeout=0.5)
    except Exception as e:
        pass



def scan_log4j():
    processes = glob.glob('/proc/[:0-9:]*')
    info = [i for i in [RuntimeInfo(procpath).base_info for procpath in processes] if i]
    report =  {'system_info':get_sys_info(), 'log4j_info':info}
    if os.environ.get('sls'):
        httplog(os.environ.get('sls'),data=info)
    return json.dumps(report)

def help():
    print('''-----------------------Log4J Local Scanner-------------------------------''')
    print('''scan log4j vulnerability from exists processes and can recurse scan fatjar''')
    print('''if sls environ is set, it can be report the result to aliyun sls using webtrack''')
    print('''the sls endpoint is 'http://{project}.{region}.log.aliyuncs.com/logstores/{logstore}/track' and should enable webtrack''')
    print('''if not a aliyun instance, use aliyun=no to ignore aliyun instance-identity''')
    print('-------------------------Good Luck-----------------------------------------''')


if __name__=='__main__':
    import sys
    if len(sys.argv)>1:
        help()
    else:
        result = scan_log4j()
        print(result)
