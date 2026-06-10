// Base de datos estática de firmas y endpoints sensibles para evaluación de riesgo

export const Wordlists = {
  // CRÍTICO: Paneles de administración, backups y archivos expuestos
  critical: [
    'admin', 'admin.php', 'admin.html', 'dashboard', 'dashboard.php',
    'controlpanel', 'cpanel', 'admin-panel', 'admin/login', 'admin/auth',
    'debug', 'debug.php', 'metrics', 'METRICS', 'actuator', 'actuator/health',
    'actuator/env', 'admin/config', 'admin/settings', 'dashboard/admin',
    'debug/info', 'trace', 'TRACE', 'ADMIN', 'DEBUG',
    // Backups
    'backup', 'backup.zip', 'backup.tar.gz', 'backup.sql', 'db.sql',
    'database.sql', 'site.bak', 'backup.bak', 'data.zip', 'archive.tar',
    'backup.gz', 'site.sql', 'db.bak', 'backups', 'archive', 'BACKUP'
  ],

  // ALTO: Autenticación, configuración, cloud y secretos
  high: [
    // Config files
    'config', 'config.json', 'settings', 'settings.json', '.env',
    '.env.local', '.env.dev', '.env.prod', 'config.xml', 'settings.xml',
    'web.config', 'app.config', 'config.ini', 'wp-config.php', 'configuration',
    'configuration.json', 'config.yaml', 'config.yml', '.env.bak', '.env.example',
    'CONFIG',
    // Authentication
    'oauth', 'oauth/authorize', 'auth', 'login', 'signup', 'register',
    'password', 'reset', 'forgot-password', 'auth/token', 'oauth/callback',
    'auth/login', 'auth/register', 'auth/reset', 'oauth/v1', 'oauth2', 'oauth2/authorize',
    // Cloud & Storage
    'storage', 'files', 's3', 'bucket', 's3.amazonaws.com', 'uploads',
    'public', 'assets', 'STORAGE', 'FILES',
    // Misc Sensitive
    'phpinfo.php', 'info.php', 'test', 'test.php', 'dev', 'staging',
    'internal', 'private', '.git', '.git/config', '.htaccess',
    'server-status', 'status', 'health', 'env', 'STATUS', 'HEALTH',
    // Extensions
    '.bak', '.zip', '.tar.gz', '.sql', '.config', '.ini', '.yml', '.yaml',
    '.json', '.xml', '.log', '.gz', '.tar', '.conf', '.bkp', '.save', '~1', '~2'
  ],

  // MEDIO: APIs, webhooks, endpoints misceláneos
  medium: [
    'api', 'api/v1', 'api/v2', 'api/v3', 'rest', 'rest/v1', 'graphql',
    'api/config', 'api/settings', 'api/users', 'api/admin', 'api/auth',
    'api/keys', 'api/token', 'api/v1/config', 'api/v1/users', 'api/v1/admin',
    'rest/admin', 'rest/config', 'graphql/admin', 'api/debug', 'api/status',
    'api/health', 'API', 'REST', 'GRAPHQL',
    // Webhooks & redirects
    'redirect', 'callback', 'webhook', 'webhooks', 'notify', 'notification',
    'push', 'redirect.php',
    // Documentación
    'swagger', 'swagger.json', 'swagger.yaml', 'openapi.json', 'openapi.yaml',
    'readme', 'README', 'README.md', 'changelog.txt', 'changelog', 'version',
    'robots.txt', 'sitemap.xml', 'crossdomain.xml', 'clientaccesspolicy.xml'
  ],

  // BAJO: Archivos JS y Service Workers
  low: [
    'service-worker.js', 'sw.js', 'worker.js', 'manifest.json', 'app.js',
    'main.js', 'bundle.js', 'scripts.js', 'config.js', 'init.js', 'serviceworker.js'
  ]
};
