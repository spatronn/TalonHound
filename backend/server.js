import express from 'express';
import cors from 'cors';

const app = express();
const port = process.env.PORT || 3000;
const demoEmail = process.env.DEMO_EMAIL || 'demo@demo.local';
const demoPassword = process.env.DEMO_PASSWORD || 'Password1!';

app.use(cors());
app.use(express.json());

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'backend' });
});

app.post('/api/auth/login', (req, res) => {
  const { email, password } = req.body || {};

  if (email === demoEmail && password === demoPassword) {
    return res.json({
      token: 'demo-token-123',
      user: { email }
    });
  }

  return res.status(401).json({ message: 'Email veya şifre hatalı' });
});

app.listen(port, () => {
  console.log(`Backend listening on :${port}`);
});
