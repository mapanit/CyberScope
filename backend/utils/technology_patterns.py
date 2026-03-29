"""
Паттерны для детектирования технологий
Расширяемая база технологий для сканера Wappalyzer
"""

TECHNOLOGY_PATTERNS = {
    # ============ CMS ============
    'WordPress': {
        'patterns': [r'wp-content', r'wp-includes', r'wordpress'],
        'version_patterns': [r'wordpress["\']?\s*:\s*["\']?([0-9.]+)', r'wp_version["\']?\s*=\s*["\']([0-9.]+)'],
        'category': 'CMS'
    },
    'Drupal': {
        'patterns': [r'drupal', r'/sites/', r'Drupal\.settings'],
        'version_patterns': [r'drupal["\']?\s*:\s*["\']?([0-9.]+)', r'drupalSettings.*?"version":\s*"([0-9.]+)'],
        'category': 'CMS'
    },
    'Joomla': {
        'patterns': [r'joomla', r'/modules/', r'/components/'],
        'version_patterns': [r'joomla["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'CMS'
    },
    'Magento': {
        'patterns': [r'magento', r'/skin/', r'/app/'],
        'version_patterns': [r'magento["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'CMS'
    },
    'Shopify': {
        'patterns': [r'myshopify\.com', r'shopify'],
        'version_patterns': [r'Shopify\.theme\s*=\s*{.*?"theme":\s*{.*?"id":\s*(\d+)'],
        'category': 'CMS'
    },
    
    # ============ JavaScript фреймворки ============
    'React': {
        'patterns': [r'react', r'__REACT', r'ReactDOM'],
        'version_patterns': [r'react["\']?\s*:\s*["\']?([0-9.]+)', r'<script[^>]*src=".*?react[^"]*@([0-9.]+)', r'react/([0-9.]+)'],
        'category': 'Framework'
    },
    'Vue.js': {
        'patterns': [r'vue', r'__VUE__', r'vue\.js'],
        'version_patterns': [r'vue["\']?\s*:\s*["\']?([0-9.]+)', r'<script[^>]*src=".*?vue[^"]*@([0-9.]+)', r'vue/([0-9.]+)'],
        'category': 'Framework'
    },
    'Angular': {
        'patterns': [r'angular', r'ng-app', r'ng-version'],
        'version_patterns': [r'angular["\']?\s*:\s*["\']?([0-9.]+)', r'ng-version="([0-9.]+)"'],
        'category': 'Framework'
    },
    'Next.js': {
        'patterns': [r'next\.js', r'__NEXT', r'__next'],
        'version_patterns': [r'next["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    'Nuxt.js': {
        'patterns': [r'nuxt', r'__NUXT__'],
        'version_patterns': [r'nuxt["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    'Svelte': {
        'patterns': [r'svelte', r'__SVELTE__'],
        'version_patterns': [r'svelte["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    'Ember.js': {
        'patterns': [r'ember', r'__EMBER__'],
        'version_patterns': [r'ember["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    
    # ============ JavaScript библиотеки ============
    'jQuery': {
        'patterns': [r'jquery', r'jQuery', r'\$\('],
        'version_patterns': [r'jquery["\']?\s*:\s*["\']?([0-9.]+)', r'jquery/([0-9.]+)', r'jquery-([0-9.]+)'],
        'category': 'Library'
    },
    'Lodash': {
        'patterns': [r'lodash', r'_\.[a-zA-Z]'],
        'version_patterns': [r'lodash["\']?\s*:\s*["\']?([0-9.]+)', r'lodash@([0-9.]+)', r'lodash/([0-9.]+)'],
        'category': 'Library'
    },
    'Moment.js': {
        'patterns': [r'moment\.js', r'moment\('],
        'version_patterns': [r'moment["\']?\s*:\s*["\']?([0-9.]+)', r'moment@([0-9.]+)', r'moment/([0-9.]+)'],
        'category': 'Library'
    },
    'Day.js': {
        'patterns': [r'day\.js', r'dayjs', r'dayjs\('],
        'version_patterns': [r'dayjs["\']?\s*:\s*["\']?([0-9.]+)', r'dayjs@([0-9.]+)'],
        'category': 'Library'
    },
    'Axios': {
        'patterns': [r'axios', r'axios\.get', r'axios\.post'],
        'version_patterns': [r'axios["\']?\s*:\s*["\']?([0-9.]+)', r'axios@([0-9.]+)', r'axios/([0-9.]+)'],
        'category': 'Library'
    },
    'Fetch API': {
        'patterns': [r'fetch\('],
        'version_patterns': [],
        'category': 'Library'
    },
    'D3.js': {
        'patterns': [r'd3\.js', r'd3\.[a-z]+', r'd3js'],
        'version_patterns': [r'd3["\']?\s*:\s*["\']?([0-9.]+)', r'd3@([0-9.]+)'],
        'category': 'Library'
    },
    'Underscore.js': {
        'patterns': [r'underscore\.js', r'_\.[a-zA-Z]'],
        'version_patterns': [r'underscore["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Library'
    },
    'Handlebars': {
        'patterns': [r'handlebars', r'Handlebars\.compile'],
        'version_patterns': [r'handlebars["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Library'
    },
    'Knockout.js': {
        'patterns': [r'knockout', r'ko\.observableArray'],
        'version_patterns': [r'knockout["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Library'
    },
    'Three.js': {
        'patterns': [r'three\.js', r'THREE\.[A-Z]'],
        'version_patterns': [r'three["\']?\s*:\s*["\']?([0-9.]+)', r'three@([0-9.]+)'],
        'category': 'Library'
    },
    'Babylon.js': {
        'patterns': [r'babylon\.js', r'babylon\.min\.js'],
        'version_patterns': [r'babylon["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Library'
    },
    'Chart.js': {
        'patterns': [r'chart\.js', r'Chart\('],
        'version_patterns': [r'chart\.js["\']?\s*:\s*["\']?([0-9.]+)', r'chart\.js@([0-9.]+)'],
        'category': 'Library'
    },
    'Plotly': {
        'patterns': [r'plotly', r'Plotly\.newPlot'],
        'version_patterns': [r'plotly["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Library'
    },
    'ECharts': {
        'patterns': [r'echarts', r'echartsjs'],
        'version_patterns': [r'echarts["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Library'
    },
    'Socket.io': {
        'patterns': [r'socket\.io', r'socketio'],
        'version_patterns': [r'socket\.io["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Library'
    },
    'Framer Motion': {
        'patterns': [r'framer-motion', r'framer motion', r'motion\('],
        'version_patterns': [r'framer-motion["\']?\s*:\s*["\']?([0-9.]+)', r'framer-motion@([0-9.]+)'],
        'category': 'Animation Library'
    },
    'Animate.css': {
        'patterns': [r'animate\.css', r'animated'],
        'version_patterns': [r'animate\.css@([0-9.]+)'],
        'category': 'Animation Library'
    },
    'GSAP': {
        'patterns': [r'gsap', r'TweenMax', r'TimelineMax'],
        'version_patterns': [r'gsap["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Animation Library'
    },
    'AOS': {
        'patterns': [r'aos\.js', r'aos\.css', r'AOS\.init'],
        'version_patterns': [r'aos@([0-9.]+)'],
        'category': 'Animation Library'
    },
    'Lottie': {
        'patterns': [r'lottie', r'lottie-web'],
        'version_patterns': [r'lottie["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Animation Library'
    },
    'Code.js': {
        'patterns': [r'code\.js', r'codejs', r'@code/js'],
        'version_patterns': [r'code\.js["\']?\s*:\s*["\']?([0-9.]+)', r'code\.js@([0-9.]+)'],
        'category': 'Library'
    },
    'Prism.js': {
        'patterns': [r'prism\.js', r'prism\.css'],
        'version_patterns': [r'prism@([0-9.]+)'],
        'category': 'Code Highlighting'
    },
    'Highlight.js': {
        'patterns': [r'highlight\.js', r'highlightjs'],
        'version_patterns': [r'highlight\.js["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Code Highlighting'
    },
    'Clipboard.js': {
        'patterns': [r'clipboard\.js', r'clipboard\('],
        'version_patterns': [r'clipboard\.js@([0-9.]+)'],
        'category': 'Library'
    },
    'Swiper': {
        'patterns': [r'swiper', r'swiper-bundle'],
        'version_patterns': [r'swiper["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Library'
    },
    'Slick': {
        'patterns': [r'slick\.js', r'slick-carousel'],
        'version_patterns': [r'slick@([0-9.]+)'],
        'category': 'Library'
    },
    'Owl Carousel': {
        'patterns': [r'owl\.carousel', r'owlcarousel'],
        'version_patterns': [r'owl\.carousel@([0-9.]+)'],
        'category': 'Library'
    },
    'Lightbox': {
        'patterns': [r'lightbox', r'lightboxjs'],
        'version_patterns': [r'lightbox@([0-9.]+)'],
        'category': 'Library'
    },
    'Fancybox': {
        'patterns': [r'fancybox', r'fancy_box'],
        'version_patterns': [r'fancybox@([0-9.]+)'],
        'category': 'Library'
    },
    'Popper.js': {
        'patterns': [r'popper\.js', r'popperjs'],
        'version_patterns': [r'popper\.js["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Library'
    },
    'Tooltip.js': {
        'patterns': [r'tooltip\.js', r'@popper/tooltip'],
        'version_patterns': [r'tooltip\.js@([0-9.]+)'],
        'category': 'Library'
    },
    'Typed.js': {
        'patterns': [r'typed\.js', r'typedjs'],
        'version_patterns': [r'typed\.js@([0-9.]+)'],
        'category': 'Library'
    },
    'Particles.js': {
        'patterns': [r'particles\.js', r'particlesjs'],
        'version_patterns': [r'particles\.js@([0-9.]+)'],
        'category': 'Library'
    },
    'ScrollReveal': {
        'patterns': [r'scrollreveal', r'scroll-reveal'],
        'version_patterns': [r'scrollreveal@([0-9.]+)'],
        'category': 'Library'
    },
    'Wow.js': {
        'patterns': [r'wow\.js', r'wowjs'],
        'version_patterns': [r'wow\.js@([0-9.]+)'],
        'category': 'Library'
    },
    'Match Height': {
        'patterns': [r'matchheight', r'match-height'],
        'version_patterns': [r'match-height@([0-9.]+)'],
        'category': 'Library'
    },
    'Isotope': {
        'patterns': [r'isotope', r'isotopejs'],
        'version_patterns': [r'isotope@([0-9.]+)'],
        'category': 'Library'
    },
    'Infinite Scroll': {
        'patterns': [r'infinite.?scroll', r'infinitescroll'],
        'version_patterns': [r'infinite-scroll@([0-9.]+)'],
        'category': 'Library'
    },
    'Masonry': {
        'patterns': [r'masonry', r'mansory'],
        'version_patterns': [r'masonry@([0-9.]+)'],
        'category': 'Library'
    },
    'Validator.js': {
        'patterns': [r'validator\.js', r'validatorjs'],
        'version_patterns': [r'validator\.js@([0-9.]+)'],
        'category': 'Form Validation'
    },
    'Parsley.js': {
        'patterns': [r'parsley\.js', r'parsleyjs'],
        'version_patterns': [r'parsley@([0-9.]+)'],
        'category': 'Form Validation'
    },
    
    # ============ CSS фреймворки ============
    'Bootstrap': {
        'patterns': [r'bootstrap\.js', r'bootstrap\.css', r'/bootstrap["\']'],
        'version_patterns': [r'bootstrap["\']?\s*:\s*["\']?([0-9.]+)', r'bootstrap@([0-9.]+)', r'bootstrap/([0-9.]+)'],
        'category': 'CSS Framework'
    },
    'Tailwind CSS': {
        'patterns': [r'tailwind', r'tailwindcss'],
        'version_patterns': [r'tailwind["\']?\s*:\s*["\']?([0-9.]+)', r'tailwindcss@([0-9.]+)'],
        'category': 'CSS Framework'
    },
    'Foundation': {
        'patterns': [r'foundation', r'foundation\.css'],
        'version_patterns': [r'foundation["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'CSS Framework'
    },
    'Bulma': {
        'patterns': [r'bulma\.css', r'bulma'],
        'version_patterns': [r'bulma["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'CSS Framework'
    },
    'Material UI': {
        'patterns': [r'material-ui', r'@mui'],
        'version_patterns': [r'@mui["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'CSS Framework'
    },
    'Ant Design': {
        'patterns': [r'antd', r'ant-design'],
        'version_patterns': [r'antd@([0-9.]+)'],
        'category': 'CSS Framework'
    },
    'Chakra UI': {
        'patterns': [r'chakra', r'@chakra-ui'],
        'version_patterns': [r'@chakra-ui["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'CSS Framework'
    },
    'mantine': {
        'patterns': [r'@mantine'],
        'version_patterns': [r'@mantine["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'CSS Framework'
    },
    'Semantic UI': {
        'patterns': [r'semantic\.ui', r'semanticui'],
        'version_patterns': [r'semantic-ui@([0-9.]+)'],
        'category': 'CSS Framework'
    },
    'Font Awesome': {
        'patterns': [r'fontawesome', r'font-awesome'],
        'version_patterns': [r'font-awesome@([0-9.]+)', r'fontawesome["\']?\s*:\s*["\']?([0-9.]+)', r'font-awesome/([0-9.]+)'],
        'category': 'Icon Library'
    },
    'Material Icons': {
        'patterns': [r'material.?icons'],
        'version_patterns': [],
        'category': 'Icon Library'
    },
    'Bootstrap Icons': {
        'patterns': [r'bootstrap.?icons'],
        'version_patterns': [],
        'category': 'Icon Library'
    },
    
    # ============ Серверные технологии ============
    'Apache': {
        'patterns': [r'Apache'],
        'version_patterns': [r'Apache/([0-9.]+)'],
        'category': 'Server'
    },
    'Nginx': {
        'patterns': [r'nginx'],
        'version_patterns': [r'nginx/([0-9.]+)'],
        'category': 'Server'
    },
    'IIS': {
        'patterns': [r'IIS'],
        'version_patterns': [r'IIS/([0-9.]+)'],
        'category': 'Server'
    },
    'Lighttpd': {
        'patterns': [r'lighttpd'],
        'version_patterns': [r'lighttpd/([0-9.]+)'],
        'category': 'Server'
    },
    
    # ============ Языки программирования ============
    'PHP': {
        'patterns': [r'PHP', r'php'],
        'version_patterns': [r'PHP/([0-9.]+)'],
        'category': 'Language'
    },
    'Python': {
        'patterns': [r'python', r'django', r'flask', r'fastapi', r'x-powered-by.*python'],
        'version_patterns': [r'Python["\']?\s*:\s*["\']?([0-9.]+)', r'python["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Language'
    },
    'Java': {
        'patterns': [r'java', r'tomcat'],
        'version_patterns': [r'Java/([0-9.]+)', r'tomcat/([0-9.]+)'],
        'category': 'Language'
    },
    'TypeScript': {
        'patterns': [r'typescript', r'\.ts"', r'<script[^>]*lang="ts"'],
        'version_patterns': [r'typescript["\']?\s*:\s*["\']?([0-9.]+)', r'typescript@([0-9.]+)'],
        'category': 'Language'
    },
    
    # ============ Python фреймворки ============
    'Django': {
        'patterns': [r'django'],
        'version_patterns': [r'django["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    'Flask': {
        'patterns': [r'flask'],
        'version_patterns': [r'flask["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    'FastAPI': {
        'patterns': [r'fastapi', r'from fastapi', r'FastAPI\(', r'starlette', r'uvicorn', r'x-powered-by.*fastapi', r'swagger-ui', r'swagger.*openapi'],
        'version_patterns': [r'fastapi["\']?\s*:\s*["\']?([0-9.]+)', r'fastapi@([0-9.]+)', r'fastapi>=([0-9.]+)', r'fastapi==([0-9.]+)'],
        'category': 'Framework'
    },
    'Pyramid': {
        'patterns': [r'pyramid'],
        'version_patterns': [r'pyramid["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    'Bottle': {
        'patterns': [r'bottle'],
        'version_patterns': [r'bottle["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    'Tornado': {
        'patterns': [r'tornado'],
        'version_patterns': [r'tornado["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    
    # ============ Node.js фреймворки ============
    'Express': {
        'patterns': [r'express\.js', r'express'],
        'version_patterns': [r'express["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    'Node.js': {
        'patterns': [r'node\.js', r'express'],
        'version_patterns': [r'node["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Runtime'
    },
    'Koa': {
        'patterns': [r'koa'],
        'version_patterns': [r'koa@([0-9.]+)'],
        'category': 'Framework'
    },
    'Fastify': {
        'patterns': [r'fastify'],
        'version_patterns': [r'fastify@([0-9.]+)'],
        'category': 'Framework'
    },
    'Nest.js': {
        'patterns': [r'nestjs', r'@nestjs'],
        'version_patterns': [r'@nestjs["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    'Hapi.js': {
        'patterns': [r'hapi\.js', r'hapijs'],
        'version_patterns': [r'hapi@([0-9.]+)'],
        'category': 'Framework'
    },
    'Meteor': {
        'patterns': [r'meteor'],
        'version_patterns': [r'meteor["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Framework'
    },
    'Sails.js': {
        'patterns': [r'sails\.js', r'sailsjs'],
        'version_patterns': [r'sails@([0-9.]+)'],
        'category': 'Framework'
    },
    
    # ============ .NET фреймворки ============
    'ASP.NET': {
        'patterns': [r'asp\.net', r'\.NET'],
        'version_patterns': [r'ASP\.NET/([0-9.]+)'],
        'category': 'Framework'
    },
    
    # ============ Analytics ============
    'Google Analytics': {
        'patterns': [r'google-analytics', r'analytics\.js', r'ga\(', r'gtag'],
        'version_patterns': [],
        'category': 'Analytics'
    },
    'Google Tag Manager': {
        'patterns': [r'google tag manager', r'gtm\.js', r'googletagmanager'],
        'version_patterns': [],
        'category': 'Analytics'
    },
    'Mixpanel': {
        'patterns': [r'mixpanel'],
        'version_patterns': [r'mixpanel["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Analytics'
    },
    'Hotjar': {
        'patterns': [r'hotjar'],
        'version_patterns': [],
        'category': 'Analytics'
    },
    'Segment': {
        'patterns': [r'segment', r'analytics\.js'],
        'version_patterns': [],
        'category': 'Analytics'
    },
    'Matomo': {
        'patterns': [r'matomo', r'piwik'],
        'version_patterns': [],
        'category': 'Analytics'
    },
    
    # ============ CDN и облако ============
    'Cloudflare': {
        'patterns': [r'cloudflare', r'cf-ray'],
        'version_patterns': [],
        'category': 'CDN'
    },
    'AWS': {
        'patterns': [r'aws', r'amazon', r's3\.amazonaws'],
        'version_patterns': [],
        'category': 'Cloud'
    },
    'Azure': {
        'patterns': [r'azure', r'microsoft'],
        'version_patterns': [],
        'category': 'Cloud'
    },
    'Google Cloud': {
        'patterns': [r'google.?cloud', r'gcp'],
        'version_patterns': [],
        'category': 'Cloud'
    },
    'Netlify': {
        'patterns': [r'netlify'],
        'version_patterns': [],
        'category': 'CDN'
    },
    'Vercel': {
        'patterns': [r'vercel'],
        'version_patterns': [],
        'category': 'CDN'
    },
    
    # ============ E-commerce ============
    'WooCommerce': {
        'patterns': [r'woocommerce'],
        'version_patterns': [r'woocommerce["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'E-Commerce'
    },
    'PrestaShop': {
        'patterns': [r'prestashop'],
        'version_patterns': [r'prestashop["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'E-Commerce'
    },
    'BigCommerce': {
        'patterns': [r'bigcommerce'],
        'version_patterns': [r'bigcommerce["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'E-Commerce'
    },
    'Shopware': {
        'patterns': [r'shopware'],
        'version_patterns': [r'shopware["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'E-Commerce'
    },
    
    # ============ Build инструменты ============
    'Webpack': {
        'patterns': [r'webpack', r'__webpack'],
        'version_patterns': [r'webpack["\']?\s*:\s*["\']?([0-9.]+)'],
        'category': 'Build Tool'
    },
    'Babel': {
        'patterns': [r'babel', r'@babel'],
        'version_patterns': [r'babel["\']?\s*:\s*["\']?([0-9.]+)', r'@babel/core@([0-9.]+)'],
        'category': 'Build Tool'
    },
    'Vite': {
        'patterns': [r'vite', r'__vite__'],
        'version_patterns': [r'vite@([0-9.]+)'],
        'category': 'Build Tool'
    },
    'Rollup': {
        'patterns': [r'rollup'],
        'version_patterns': [r'rollup@([0-9.]+)'],
        'category': 'Build Tool'
    },
    'Esbuild': {
        'patterns': [r'esbuild'],
        'version_patterns': [r'esbuild@([0-9.]+)'],
        'category': 'Build Tool'
    },
    'Parcel': {
        'patterns': [r'parcel'],
        'version_patterns': [r'parcel@([0-9.]+)'],
        'category': 'Build Tool'
    },
    'Gulp': {
        'patterns': [r'gulp'],
        'version_patterns': [r'gulp@([0-9.]+)'],
        'category': 'Build Tool'
    },
    'Grunt': {
        'patterns': [r'grunt'],
        'version_patterns': [r'grunt@([0-9.]+)'],
        'category': 'Build Tool'
    },
    
    # ============ Package managers ============
    'npm': {
        'patterns': [r'npm'],
        'version_patterns': [r'npm\s+([0-9.]+)'],
        'category': 'Package Manager'
    },
    'yarn': {
        'patterns': [r'yarn'],
        'version_patterns': [r'yarn\s+([0-9.]+)'],
        'category': 'Package Manager'
    },
    'pnpm': {
        'patterns': [r'pnpm'],
        'version_patterns': [r'pnpm\s+([0-9.]+)'],
        'category': 'Package Manager'
    },
    'pip': {
        'patterns': [r'pip'],
        'version_patterns': [r'pip\s+([0-9.]+)'],
        'category': 'Package Manager'
    },
}
