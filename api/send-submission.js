import nodemailer from 'nodemailer';

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  const { loanOfficer, emails, loanType, borrowerName, propertyAddress, loanNumber, submittedBy, details } = req.body || {};
  if (!loanOfficer || !loanType || !Array.isArray(emails) || emails.length === 0) {
    return res.status(400).json({ error: 'Missing required submission fields' });
  }

  const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASS
    }
  });

  const text = [
    'Loan Submission',
    `Loan Officer: ${loanOfficer}`,
    `Loan Type: ${loanType}`,
    `Borrower Name: ${borrowerName || 'n/a'}`,
    `Property Address: ${propertyAddress || 'n/a'}`,
    `Loan Number: ${loanNumber || 'n/a'}`,
    `Submitted By: ${submittedBy || 'n/a'}`,
    '',
    'Details:',
    JSON.stringify(details || {}, null, 2)
  ].join('\n');

  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to: emails.join(','),
    subject: `${loanType.charAt(0).toUpperCase() + loanType.slice(1)} Submission - ${borrowerName || 'Borrower'}`,
    text,
    replyTo: process.env.MAIL_FROM
  });

  return res.status(200).json({ ok: true, via: 'gmail' });
}
