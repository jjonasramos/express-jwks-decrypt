import express, { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import jwktopem from 'jwk-to-pem';
import axios from 'axios';
import morgan from 'morgan';
import cors from 'cors';

const app = express();

app.use(express.json());
app.use(cors());
app.use(morgan('dev'));

app.get('/', (req: Request, res: Response) => {
  res.send('Hello World!');
});

app.post('/verify', async (req: Request, res: Response) => {
  let { token } = req.body;

  let decodedToken = jwt.decode(token, { complete: true });

  let kid = <unknown> decodedToken!.header.kid;

  const jwksResponse = await axios.get('https://cluster.us.qlikcloud.com/.well-known/jwks.json').then((response) => response.data);

  const [firstKey] = jwksResponse.keys.filter((key: any) => key.kid === kid);
  const publicKey = jwktopem(firstKey);
  try {
    const decoded = jwt.verify(token, publicKey);
    const user = await axios.get('https://cluster.us.qlikcloud.com/api/v1/users/me', {
      headers: {
        Authorization: `Bearer ${token}`,
      }
    });

    if(!user.data) return res.status(400).json({ error: 'User not found' });
    
    return res.json({ decoded, user: user.data });
  } catch (e) {
    return res.status(400).json({ error: 'Error' });
  }
});


app.listen(3000, () => {
  console.log('Server is running on port 3000');
});