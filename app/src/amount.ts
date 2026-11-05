/** Format atomic units without ever passing through a floating-point Number. */
export function amount(value: string | null | undefined): string {
  if (value == null) return '—';
  if (!/^(0|[1-9][0-9]*)$/.test(value)) throw new Error('Invalid atomic amount');
  const n = BigInt(value), unit = 1_000_000_000_000n;
  const whole = (n / unit).toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
  const fraction = (n % unit).toString().padStart(12, '0').replace(/0+$/, '').padEnd(2, '0');
  return `${whole}.${fraction}`;
}
