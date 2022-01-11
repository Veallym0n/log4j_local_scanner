# log4j_local_scanner
a python3 script for scan log4j vulnerability from processes and fatjar


```
def help():
    print('''-----------------------Log4J Local Scanner-------------------------------''')
    print('''scan log4j vulnerability from exists processes and can recurse scan fatjar''')
    print('''if sls environ is set, it can be report the result to aliyun sls using webtrack''')
    print('''the sls endpoint is 'http://{project}.{region}.log.aliyuncs.com/logstores/{logstore}/track' and should enable webtrack''')
    print('''if runnig without aliyun instance, use aliyun=no to ignore aliyun instance-identity read''')
    print('-------------------------Good Luck-----------------------------------------''')

```

```
# python3 log4jscan.py|jq .

{
  "system_info": {
    "hostname": "myEcs",
    "private-ipv4": "172.0.0.1",
    "zone-id": "cn-xx-c",
    "serial-number": "xxx-xxx-xx-xxxxx-xxxxx-xxx",
    "instance-id": "i-xxxxxxxxxxxx",
    "region-id": "cn-xx",
    "owner-account-id": "000000000",
    "mac": "00:02:00:00:00:00",
    "image-id": "centos_8_2_x64_20G_alibase_20201120.vhd",
    "instance-type": "ecs.t5-lc1m2.small"
  },
  "log4j_info": [
    {
      "pid": "2084393",
      "envfix": "False",
      "cmdfix": "False",
      "jar_info": [
        {
          "version": "version=2.14.1",
          "path": "/data/xx/log4j/test/src/_log4j-core-2.14.1.jar",
          "JndiLookup.class": "True"
        },
        {
          "version": "version=2.14.1",
          "path": "/tmp/p.jar/pp.jar/p.jar/fafa/a.jar"
        },
        {
          "version": "version=2.14.1",
          "path": "/tmp/p.jar/p.jar/fafa/a.jar"
        },
        {
          "version": "version=2.14.1",
          "path": "/tmp/p.jar/ppp.jar/p.jar/fafa/a.jar"
        }
      ]
    },
    {
      "pid": "2084404",
      "envfix": "False",
      "cmdfix": "False",
      "jar_info": [
        {
          "version": "version=2.14.1",
          "path": "/data/xx/log4j/test/src/_log4j-core-2.14.1.jar",
          "JndiLookup.class": "True"
        },
        {
          "version": "version=2.14.1",
          "path": "/tmp/p.jar/pp.jar/p.jar/fafa/a.jar"
        },
        {
          "version": "version=2.14.1",
          "path": "/tmp/p.jar/p.jar/fafa/a.jar"
        },
        {
          "version": "version=2.14.1",
          "path": "/tmp/p.jar/ppp.jar/p.jar/fafa/a.jar"
        }
      ]
    }
  ]
}
```
