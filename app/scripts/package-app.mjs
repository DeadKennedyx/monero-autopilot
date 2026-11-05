import {readFileSync,writeFileSync,mkdirSync} from 'node:fs';
const base=new URL('../dist/',import.meta.url);
let html=readFileSync(new URL('index.html',base),'utf8');
html=html.replace(/<script\b[^>]*src="([^"]+)"[^>]*><\/script>/g,(_,path)=>`<script type="module">${readFileSync(new URL(path,base),'utf8').replace(/<\/script/gi,'<\\/script')}</script>`);
html=html.replace(/<link\b[^>]*href="([^"]+\.css)"[^>]*>/g,(_,path)=>`<style>${readFileSync(new URL(path,base),'utf8')}</style>`);
const output=new URL('../web/',import.meta.url);
mkdirSync(output,{recursive:true});
writeFileSync(new URL('index.html',output),html);
console.log('Mainnet desktop interface embedded.');
