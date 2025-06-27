const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
app.use(bodyParser.json({ limit: '1mb' }));
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'ok' });
});

app.post('/webhook', async (req, res) => {
  try {
    const { encryptedData, encryptedKey, iv } = req.body;

    const privateKey = process.env.META_PRIVATE_KEY.replace(/\\n/g, '\n');
    const bufferEncryptedKey = Buffer.from(encryptedKey, 'base64');

    const decryptedAESKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256'
      },
      bufferEncryptedKey
    );

    const decipher = crypto.createDecipheriv('aes-256-gcm', decryptedAESKey, Buffer.from(iv, 'base64'));
    decipher.setAuthTag(Buffer.from(req.body.authTag, 'base64'));

    let decrypted = decipher.update(encryptedData, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    const jsonData = JSON.parse(decrypted);

    console.log('Decrypted Payload:', jsonData);

    // Send to your Make.com webhook
    await fetch(process.env.MAKE_WEBHOOK_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(jsonData)
    });

    res.status(200).send('ACK');
  } catch (error) {
    console.error('Decryption error:', error);
    res.status(500).send('Error');
  }
});

app.get('/webhook', (req, res) => {
  res.status(200).send('Webhook is alive!');
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
