import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json({ type: '*/*' }));

app.post('/', (req, res) => {
  const encryptionKeyB64 = req.header('X-Encrypt-Key');
  const encryptionIVB64 = req.header('X-Encrypt-IV');

  if (!encryptionKeyB64 || !encryptionIVB64) {
    return res.status(400).json({ error: 'Missing encryption headers' });
  }

  const key = Buffer.from(encryptionKeyB64, 'base64');
  const iv = Buffer.from(encryptionIVB64, 'base64');

  const responseData = JSON.stringify({ status: 'INIT received' });

  const cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(responseData, 'utf8', 'base64');
  encrypted += cipher.final('base64');

  res.setHeader('Content-Type', 'text/plain');
  res.status(200).send(encrypted);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
