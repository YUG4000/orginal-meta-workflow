import express from 'express';
import bodyParser from 'body-parser';
import crypto from 'crypto';
import dotenv from 'dotenv';

dotenv.config();

const app = express();
app.use(bodyParser.json());

app.post('/', (req, res) => {
  const aesKey = req.headers['x-aes-key'];
  const aesIV = req.headers['x-aes-iv'];

  if (!aesKey || !aesIV) {
    return res.status(400).send('Missing encryption headers');
  }

  const responseData = JSON.stringify({
    status: 'INIT received'
  });

  try {
    const keyBuffer = Buffer.from(aesKey, 'base64');
    const ivBuffer = Buffer.from(aesIV, 'base64');

    const cipher = crypto.createCipheriv('aes-256-cbc', keyBuffer, ivBuffer);
    let encrypted = cipher.update(responseData, 'utf8', 'base64');
    encrypted += cipher.final('base64');

    res.status(200).send(encrypted);
  } catch (error) {
    console.error('Encryption failed:', error);
    res.status(500).send('Encryption error');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
