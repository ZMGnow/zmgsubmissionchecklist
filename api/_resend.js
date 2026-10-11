// All ZMG email goes out through Resend from @send.zmgnow.com (Steven, Oct 2026).
// Gmail SMTP was removed on purpose -- do not add it back.
// Requires RESEND_API_KEY in the Vercel project settings.
export const FROM_ADDRESS = 'ZMG Loan Submission Portal <notifications@send.zmgnow.com>';

export const MISSING_API_KEY_ERROR = 'RESEND_API_KEY environment variable is missing in Vercel.';

export async function sendEmail({ to, subject, text, html, replyTo }) {
  const apiKey = process.env.RESEND_API_KEY;
  if (!apiKey) throw new Error(MISSING_API_KEY_ERROR);
  const payload = { from: FROM_ADDRESS, to: [].concat(to || []), subject, text, html };
  const replyToAddresses = [].concat(replyTo || []).filter(Boolean);
  if (replyToAddresses.length) payload.reply_to = replyToAddresses;
  const response = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
    body: JSON.stringify(payload)
  });
  const result = await response.json().catch(() => null);
  if (!response.ok || !result || !result.id) {
    const message = result && (result.message || (result.error && result.error.message));
    throw new Error(message || `Resend API responded with status ${response.status}.`);
  }
  return result;
}
