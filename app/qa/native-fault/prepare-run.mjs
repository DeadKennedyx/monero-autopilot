import {mkdirSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
import {createRun} from './files.mjs';
import {initialState} from './core.mjs';
import {atomicJson} from './files.mjs';
const [id,socks='19050',proxy='19089']=process.argv.slice(2);
const {root,config}=createRun(id,Number(socks),Number(proxy));
for(const name of ['tor-data','tor-service'])mkdirSync(join(root,name));
const quoted=path=>'"'+path.replaceAll('\\','/')+'"';
writeFileSync(join(root,'tor.defaults'),'');
writeFileSync(join(root,'torrc'),[
  `DataDirectory ${quoted(join(root,'tor-data'))}`,
  `SocksPort 127.0.0.1:${config.socksPort}`,
  'SocksPolicy accept 127.0.0.1', 'SocksPolicy reject *', 'SafeSocks 1',
  `HiddenServiceDir ${quoted(join(root,'tor-service'))}`, 'HiddenServiceVersion 3',
  `HiddenServicePort 18089 127.0.0.1:${config.proxyPort}`,
  'AvoidDiskWrites 1', 'Log warn stderr',
].join('\n')+'\n');
atomicJson(join(root,'proxy-state.json'),initialState());
console.log(JSON.stringify({outcome:'prepared_no_process_started',run:id}));
