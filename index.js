import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(express.json({ type: '*/*' }));

const privateKey = process.env.PRIVATE_KEY.replace(/\\n/g, '\n');

app.post('/', (req, res) => {
  const { encrypted_flow_data, encrypted_aes_key, initial_vector } = req.body;

  // Missing required fields
  if (!encrypted_flow_data || !encrypted_aes_key || !initial_vector) {
    return res.status(400).json({ error: 'Missing encryption fields' });
  }

  try {
    // 1. Decrypt AES key using our RSA private key
    const aesKey = crypto.privateDecrypt(
      {
        key: privateKey,
        padding: crypto.constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
      },
      Buffer.from(encrypted_aes_key, 'base64')
    );

    // 2. Decrypt flow data using AES key and IV
    const iv = Buffer.from(initial_vector, 'base64');
    const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);

    let decrypted = decipher.update(encrypted_flow_data, 'base64', 'utf8');
    decrypted += decipher.final('utf8');

    const parsedData = JSON.parse(decrypted);
    console.log('Decrypted Request:', parsedData);

    // 3. Build a response payload
    const responseJson = JSON.stringify({ status: 'INIT successful' });

    const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
    let encrypted = cipher.update(responseJson, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    res.setHeader('Content-Type', 'text/plain');
    res.status(200).send(encrypted);
  } catch (err) {
    console.error('Error processing Meta Flow:', err);
    res.status(500).json({ error: 'Decryption/Encryption failed' });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Meta Flow server running on port ${PORT}`);
});
