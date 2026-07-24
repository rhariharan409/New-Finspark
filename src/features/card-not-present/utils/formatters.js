/**
 * Formatting utilities for Card Not Present (CNP) Fraud Detection (JS Runtime)
 */

export function formatCurrency(amount, currency = 'INR (₹)') {
  const symbol = currency.includes('USD') ? '$' : currency.includes('EUR') ? '€' : '₹';
  return `${symbol}${amount.toLocaleString('en-IN')}`;
}

export function maskCardNumber(cardNumber) {
  const clean = String(cardNumber).replace(/\D/g, '');
  if (clean.length < 4) return cardNumber;
  const last4 = clean.slice(-4);
  return `•••• •••• •••• ${last4}`;
}

export function getRiskBadgeClass(score) {
  if (score <= 30) return 'bg-emerald-100 text-emerald-800 border-emerald-300';
  if (score <= 60) return 'bg-amber-100 text-amber-800 border-amber-300';
  if (score <= 80) return 'bg-orange-100 text-orange-800 border-orange-300';
  return 'bg-red-100 text-red-800 border-red-300';
}

export function getRiskColor(score) {
  if (score <= 30) return '#059669';
  if (score <= 60) return '#d97706';
  if (score <= 80) return '#ea580c';
  return '#dc2626';
}
