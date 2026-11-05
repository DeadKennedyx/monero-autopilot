import {createRoot} from 'react-dom/client';
import {MainnetApp} from './App';
import mainnetStyle from './mainnet.css?inline';
import productStyle from './product-theme.css?inline';

const style = document.createElement('style');
style.dataset.autopilotTheme = 'mainnet';
style.textContent = mainnetStyle + '\n' + productStyle;
document.head.appendChild(style);
createRoot(document.getElementById('root')!).render(<MainnetApp/>);
