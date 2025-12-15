// Reenviar código de verificación
app.post('/resend-code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ error: 'Email requerido' });

  try {
    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
    if (user.verified) return res.status(400).json({ error: 'Usuario ya verificado' });

    const verificationToken = generateVerificationCode();
    await prisma.user.update({
      where: { email },
      data: { verificationToken }
    });

    await sendEmail(
      email,
      'Reenvío de Código de Verificación',
      `Tu nuevo código es: ${verificationToken}`,
      `<h1>Código de Verificación</h1><p>Tu nuevo código es:</p><h2>${verificationToken}</h2>`
    );

    res.json({ message: 'Código reenviado exitosamente' });
  } catch (error) {
    console.error('Error resending code:', error);
    res.status(500).json({ error: 'Error al reenviar código' });
  }
});
