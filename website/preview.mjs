import { createServer } from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { resolve, extname, sep } from 'node:path';
const directory = resolve(import.meta.dirname, 'dist');
const mime = {'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.svg':'image/svg+xml'};
const server = createServer(async (request,response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url, 'http://127.0.0.1').pathname);
    const file = resolve(directory, '.' + (pathname.endsWith('/') ? pathname + 'index.html' : pathname));
    if (!file.startsWith(directory + sep)) { response.writeHead(403); response.end(); return; }
    if (!(await stat(file)).isFile()) throw Error('not-file');
    const bytes = await readFile(file);
    response.writeHead(200, {'Content-Type':mime[extname(file)] || 'application/octet-stream','Cache-Control':'no-store','X-Content-Type-Options':'nosniff'});
    response.end(bytes);
  } catch { response.writeHead(404,{'Content-Type':'text/plain'}); response.end('Page not found'); }
});
server.listen(0,'127.0.0.1',()=>console.log('Local: http://127.0.0.1:' + server.address().port + '/'));
