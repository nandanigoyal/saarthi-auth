import nodemailer from 'nodemailer';
import logger from './logger';

export const sendMail = async (to: string, subject: string, html: string) => {
  try {
    // For local testing, we can mock it or log it
    logger.info(`Sending email to ${to} with subject "${subject}"`);
    
    const host = process.env.EMAIL_HOST;
    const port = parseInt(process.env.EMAIL_PORT || '587');
    const user = process.env.EMAIL_USER;
    const pass = process.env.EMAIL_PASS;
    const from = process.env.EMAIL_FROM || 'noreply@saarthi.health';

    if (!host || !user || !pass || user === 'mockuser' || process.env.NODE_ENV === 'test') {
      logger.info(`SMTP settings not fully configured or running in Test environment. Email logged to console: \nTo: ${to} \nSubject: ${subject}`);
      return true;
    }

    const transporter = nodemailer.createTransport({
      host,
      port,
      auth: {
        user,
        pass,
      },
    });

    const info = await transporter.sendMail({
      from,
      to,
      subject,
      html,
    });

    logger.info(`Message sent: ${info.messageId}`);
    return true;
  } catch (error) {
    logger.error('Error sending email:', error);
    return false;
  }
};
