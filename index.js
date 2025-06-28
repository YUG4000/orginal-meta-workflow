import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json({ type: '*/*' }));

app.post('/', (req, res) => {
  const encryptionKeyB64 = req.header('X-Encrypt-Key');
  const encryptionIVB64 = req.header('X-Encrypt-IV');

  const { action } = req.body || {};

  // ✅ Handle Meta's INIT action without encryption
  if (action === 'INIT') {
    return res.status(200).json({ status: 'INIT success without encryption' });
  }

  // ❌ All other actions MUST have encryption headers
  if (!encryptionKeyB64 || !encryptionIVB64) {
    return res.status(400).json({ error: 'Missing encryption headers' });
  }

  try {
    const key = Buffer.from(encryptionKeyB64, 'base64');
    const iv = Buffer.from(encryptionIVB64, 'base64');

    const responseData = JSON.stringify({ status: 'Action processed' });

    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
    let encrypted = cipher.update(responseData, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    res.setHeader('Content-Type', 'text/plain');
    res.status(200).send(encrypted);
  } catch (err) {
    console.error('Encryption error:', err);
    res.status(500).json({ error: 'Encryption failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
