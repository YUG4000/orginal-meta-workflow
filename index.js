import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json({ type: '*/*' }));

const privateKey = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');

app.post('/', (req, res) => {
  const { encrypted_flow_data, encrypted_aes_key, initial_vector } = req.body;

  if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
    return res.status(400).json({ error: 'Missing encryption fields' });
  }

  try {
    // Decrypt the AES key using RSA private key
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encrypted_aes_key, 'base64')
    );

    // Decrypt the actual flow data
    const iv = Buffer.from(initial_vector, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);

    let decrypted = decipher.update(encrypted_flow_data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    const parsedData = JSON.parse(decrypted);
    console.log('Decrypted Flow:', parsedData);

    // Build response message
    const responseMessage = JSON.stringify({ status: 'INIT successful' });

    // Encrypt the response using AES key and IV
    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encrypted = cipher.update(responseMessage, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    res.setHeader('Content-Type', 'text/plain');
    res.status(200).send(encrypted);
  } catch (error) {
    console.error('Error handling request:', error.message);
    res.status(500).json({ error: 'Failed to process encrypted request' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});
