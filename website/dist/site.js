const menuButton = document.querySelector('.menu-toggle');
const navigation = document.querySelector('#navigation');
function closeMenu() { navigation?.classList.remove('open'); menuButton?.setAttribute('aria-expanded', 'false'); menuButton?.setAttribute('aria-label', 'Open navigation'); }
menuButton?.addEventListener('click', () => {
  const open = menuButton.getAttribute('aria-expanded') !== 'true';
  navigation.classList.toggle('open', open);
  menuButton.setAttribute('aria-expanded', String(open));
  menuButton.setAttribute('aria-label', open ? 'Close navigation' : 'Open navigation');
});
navigation?.querySelectorAll('a').forEach(link => link.addEventListener('click', closeMenu));
document.addEventListener('keydown', event => { if (event.key === 'Escape') closeMenu(); });
const tabs = [...document.querySelectorAll('[data-tab]')];
const panels = [...document.querySelectorAll('[role="tabpanel"]')];
function selectTab(name, focus = false) {
  if (!tabs.some(tab => tab.dataset.tab === name)) return;
  tabs.forEach(tab => {
    const selected = tab.dataset.tab === name;
    tab.setAttribute('aria-selected', String(selected));
    tab.tabIndex = selected ? 0 : -1;
    if (selected && focus) tab.focus();
  });
  panels.forEach(panel => { panel.hidden = panel.id !== 'panel-' + name; });
  document.querySelectorAll('.preview-sidebar [data-select-tab]').forEach(button => button.classList.toggle('selected', button.dataset.selectTab === name));
  document.querySelector('#preview-section-name').textContent = { overview: 'Home', privacy: 'Privacy', wallets: 'Wallets' }[name];
}
tabs.forEach((tab, index) => {
  tab.addEventListener('click', () => selectTab(tab.dataset.tab));
  tab.addEventListener('keydown', event => {
    let target;
    if (event.key === 'ArrowRight') target = (index + 1) % tabs.length;
    if (event.key === 'ArrowLeft') target = (index + tabs.length - 1) % tabs.length;
    if (event.key === 'Home') target = 0;
    if (event.key === 'End') target = tabs.length - 1;
    if (target !== undefined) { event.preventDefault(); selectTab(tabs[target].dataset.tab, true); }
  });
});
document.querySelectorAll('[data-select-tab]').forEach(button => button.addEventListener('click', () => selectTab(button.dataset.selectTab, true)));
const balanceToggle = document.querySelector('#balance-toggle');
balanceToggle?.addEventListener('click', () => {
  const hidden = balanceToggle.getAttribute('aria-pressed') !== 'true';
  balanceToggle.setAttribute('aria-pressed', String(hidden));
  balanceToggle.setAttribute('aria-label', hidden ? 'Show balance' : 'Hide balance');
  document.querySelectorAll('[data-balance]').forEach(element => { element.textContent = hidden ? '••••••' : element.dataset.balance; });
});
const privacyDialog = document.querySelector('#privacy-dialog');
document.querySelectorAll('[data-open-privacy]').forEach(button => button.addEventListener('click', () => privacyDialog?.showModal()));
document.querySelectorAll('[data-close-dialog]').forEach(button => button.addEventListener('click', () => privacyDialog?.close()));
privacyDialog?.addEventListener('click', event => {
  if (event.target !== privacyDialog) return;
  const rect = privacyDialog.getBoundingClientRect();
  if (event.clientX < rect.left || event.clientX > rect.right || event.clientY < rect.top || event.clientY > rect.bottom) privacyDialog.close();
});

const donationCopy = document.querySelector('[data-copy-donation]');
donationCopy?.addEventListener('click', async () => {
  const address = document.querySelector('#donation-address');
  const status = document.querySelector('#donation-copy-status');
  if (!address || !status) return;
  try {
    await navigator.clipboard.writeText(address.textContent.trim());
    status.textContent = 'Address copied. Paste it into your Monero wallet.';
  } catch {
    const selection = window.getSelection();
    const range = document.createRange();
    range.selectNodeContents(address);
    selection?.removeAllRanges();
    selection?.addRange(range);
    status.textContent = 'Copy was unavailable. The address is selected so you can copy it manually.';
  }
});
