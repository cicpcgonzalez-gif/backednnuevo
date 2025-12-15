require('dotenv').config();
const { PrismaClient } = require('@prisma/client');
const nodemailer = require('nodemailer');

const prisma = new PrismaClient();

async function sendTestEmail(to) {
  console.log('Starting email test...');
  
  // 1. Buscar configuración SMTP personalizada en DB
  let settings = null;
  try {
    settings = await prisma.systemSettings.findFirst();
  } catch (dbError) {
    console.warn('Could not fetch settings from DB (using ENV fallback):', dbError.message);
  }

  let transporter;
  let fromAddress = '"MegaRifas" <noreply@megarifasapp.com>';

  if (settings && settings.smtp) {
    console.log('Using SMTP settings from Database');
    const smtp = settings.smtp;
    if (smtp.host && smtp.user && smtp.pass) {
      transporter = nodemailer.createTransport({
        host: smtp.host,
        port: Number(smtp.port) || 587,
        secure: smtp.secure === true || smtp.secure === 'true',
        auth: {
          user: smtp.user,
          pass: smtp.pass
        }
      });
      fromAddress = `"${smtp.fromName || 'MegaRifas'}" <${smtp.fromEmail || smtp.user}>`;
    }
  } 
  
  if (!transporter) {
     console.log('Using SMTP settings from Environment Variables');
     if (process.env.SMTP_HOST) {
        transporter = nodemailer.createTransport({
            host: process.env.SMTP_HOST,
            port: Number(process.env.SMTP_PORT) || 587,
            secure: process.env.SMTP_SECURE === 'true',
            auth: {
                user: process.env.SMTP_USER,
                pass: process.env.SMTP_PASS
            }
        });
     } else {
         console.log('No SMTP configuration found (DB or ENV). Using Mock/Ethereal.');
         transporter = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            secure: false,
            auth: {
                user: 'ethereal_user',
                pass: 'ethereal_pass'
            }
        });
     }
  }

  try {
    const info = await transporter.sendMail({
      from: fromAddress,
      to,
      subject: 'Prueba de Correo - MegaRifas',
      text: 'Este es un correo de prueba para verificar que el servicio de correos está activo.',
      html: '<h1>Prueba Exitosa</h1><p>El servicio de correos está funcionando correctamente.</p>'
    });

    console.log('Message sent: %s', info.messageId);
    if (nodemailer.getTestMessageUrl(info)) {
        console.log('Preview URL: %s', nodemailer.getTestMessageUrl(info));
    }
  } catch (error) {
    console.error('Error sending email:', error);
  } finally {
    await prisma.$disconnect();
  }
}

sendTestEmail('cicpcgonzalez@gmail.com');
