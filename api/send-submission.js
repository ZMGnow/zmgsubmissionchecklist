import nodemailer from 'nodemailer';

function safe(value) {
  if (value === undefined || value === null) return '';
  if (Array.isArray(value)) return value.filter(Boolean).join(', ');
  return String(value).trim();
}

function sectionBlock(title, data) {
  const lines = Object.entries(data || {})
    .filter(([, value]) => {
      if (Array.isArray(value)) return value.length > 0;
      return safe(value) !== '';
    })
    .map(([key, value]) => {
      const label = key
        .replace(/([A-Z])/g, ' $1')
        .replace(/_/g, ' ')
        .replace(/^./, (s) => s.toUpperCase());
      return `${label}: ${safe(value)}`;
    });

  return [
    `=== ${title} ===`,
    ...(lines.length ? lines : ['No data provided.']),
    ''
  ].join('\n');
}

function parseEmails(value) {
  return String(value || '')
    .split(',')
    .map((email) => email.trim())
    .filter(Boolean);
}

// Secure backend mapping for Loan Officer / Team → recipient list.
// Frontend may display recipients, but backend enforces the final routing.
const emailRoutes = {
  'Steven Zin': ['Loanprocessing@zmgnow.com', 'zinteam@zmgnow.com'],
  'Teresa Clark': ['Loanprocessing@zmgnow.com', 'teamclark@tdcmtg.com'],
  'Cari LaMere': ['Loanprocessing@zmgnow.com', 'lamereteam@zmgnow.com'],
  'Chasten Gerhart': ['Loanprocessing@zmgnow.com', 'chastenteam@zmgnow.com']
};

function htmlSection(title, data) {
  const rows = Object.entries(data || {})
    .filter(([, value]) => {
      if (Array.isArray(value)) return value.length > 0;
      return safe(value) !== '';
    })
    .map(([key, value]) => {
      const label = key
        .replace(/([A-Z])/g, ' $1')
        .replace(/_/g, ' ')
        .replace(/^./, (s) => s.toUpperCase());

      return `
        <tr>
          <td style="padding:8px 12px;border:1px solid #d9e2ec;background:#f8fafc;font-weight:600;width:260px;vertical-align:top;">${label}</td>
          <td style="padding:8px 12px;border:1px solid #d9e2ec;vertical-align:top;">${safe(value)}</td>
        </tr>
      `;
    })
    .join('');

  return `
    <div style="margin:0 0 24px 0;">
      <h2 style="margin:0 0 12px 0;font-size:18px;color:#0e6b72;font-family:Arial,sans-serif;">${title}</h2>
      <table style="width:100%;border-collapse:collapse;font-family:Arial,sans-serif;font-size:14px;color:#17212b;">
        ${rows || `
          <tr>
            <td style="padding:8px 12px;border:1px solid #d9e2ec;background:#f8fafc;font-weight:600;width:260px;">Status</td>
            <td style="padding:8px 12px;border:1px solid #d9e2ec;">No data provided.</td>
          </tr>
        `}
      </table>
    </div>
  `;
}

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = req.body || {};
    const general = body.general || {};
    const refinance = body.refinance || {};
    const purchase = body.purchase || {};

    const loanTeam = safe(general.loanTeam);
    const submissionType = safe(general.submissionType);
    const borrowerName = safe(general.borrowerName) || 'Unknown Borrower';
    const propertyAddress = safe(general.propertyAddress);
    const submittedBy = safe(general.submittedBy);

    // Secure routing: use backend mapping, ignore any attempt to override recipients.
    const routeRecipients = emailRoutes[loanTeam] || [];
    const manualEmails = parseEmails(general.emailRecipients); // frontend may send preview, but mapping wins
    const recipients = routeRecipients.length ? routeRecipients : manualEmails;

    if (!loanTeam) {
      return res.status(400).json({ error: 'Loan Officer / Team is required.' });
    }

    if (!emailRoutes[loanTeam]) {
      return res.status(400).json({ error: 'Invalid Loan Officer / Team selection.' });
    }

    if (!submissionType) {
      return res.status(400).json({ error: 'Submission Type is required.' });
    }

    if (!propertyAddress) {
      return res.status(400).json({ error: 'Property Address is required.' });
    }

    if (!submittedBy) {
      return res.status(400).json({ error: 'Submitted By is required.' });
    }

    if (!recipients.length) {
      return res.status(400).json({
        error: 'No email recipients could be determined from the selected team.'
      });
    }

    if (!process.env.SMTP_USER || !process.env.SMTP_PASS) {
      // Vercel best practice: require environment variables for SMTP credentials. [web:129]
      return res.status(500).json({
        error: 'SMTP environment variables (SMTP_USER / SMTP_PASS) are missing in Vercel.'
      });
    }

    const transporter = nodemailer.createTransport({
      service: 'gmail',
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASS
      }
    });

    const subject = `ZMG Loan Submission - ${submissionType} - ${loanTeam} - ${borrowerName}`;

    // Grouped text summary
    const emailText = [
      'ZMG Loan Submission Portal',
      '',
      sectionBlock('General Information', {
        loanOfficerTeam: loanTeam,
        submissionType,
        borrowerName,
        propertyAddress,
        loanNumber: safe(general.loanNumber),
        submittedBy,
        emailRecipients: recipients
      }),
      submissionType === 'Refinance'
        ? sectionBlock('Refinance Submission Checklist', refinance)
        : '',
      submissionType === 'Purchase'
        ? sectionBlock('Purchase Submission Checklist', purchase)
        : ''
    ].join('\n');

    // Grouped HTML summary
    const htmlGeneral = {
      loanOfficerTeam: loanTeam,
      submissionType,
      borrowerName,
      propertyAddress,
      loanNumber: safe(general.loanNumber),
      submittedBy,
      emailRecipients: recipients
    };

    const emailHtml = `
      <div style="font-family:Arial,sans-serif;background:#f4f7fb;padding:24px;color:#17212b;">
        <div style="max-width:900px;margin:0 auto;background:#ffffff;border:1px solid #d9e2ec;border-radius:16px;padding:24px;">
          <h1 style="margin:0 0 8px 0;font-size:26px;color:#17212b;">ZMG Loan Submission Portal</h1>
          <p style="margin:0 0 24px 0;color:#667085;">Completed submission received from the web portal. Review details by section below.</p>
          ${htmlSection('General Information', htmlGeneral)}
          ${submissionType === 'Refinance' ? htmlSection('Refinance Submission Checklist', refinance) : ''}
          ${submissionType === 'Purchase' ? htmlSection('Purchase Submission Checklist', purchase) : ''}
        </div>
      </div>
    `;

    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: recipients.join(','),
      subject,
      text: emailText,
      html: emailHtml,
      replyTo: process.env.SMTP_USER
    });

    return res.status(200).json({
      ok: true,
      message: 'Submission sent successfully.'
    });
  } catch (error) {
    return res.status(500).json({
      error: error.message || 'Unexpected error while sending submission.'
    });
  }
}
