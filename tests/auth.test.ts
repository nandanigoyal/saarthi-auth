import request from 'supertest';
import mongoose from 'mongoose';
import { MongoMemoryServer } from 'mongodb-memory-server';
import app from '../src/server';
import User from '../src/models/User';
import RefreshToken from '../src/models/RefreshToken';

let mongoServer: MongoMemoryServer;

beforeAll(async () => {
  mongoServer = await MongoMemoryServer.create();
  const uri = mongoServer.getUri();
  await mongoose.connect(uri);
});

afterAll(async () => {
  await User.deleteMany({});
  await RefreshToken.deleteMany({});
  await mongoose.disconnect();
  await mongoServer.stop();
});

beforeEach(async () => {
  await User.deleteMany({});
  await RefreshToken.deleteMany({});
});

describe('Authentication API Endpoints', () => {
  const mockUser = {
    name: 'Test User',
    email: 'testuser@example.com',
    password: 'password123',
    phone: '1234567890',
    age: 25,
    city: 'New Delhi',
  };

  describe('POST /api/auth/register', () => {
    it('should register a new user successfully and return tokens', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send(mockUser);

      expect(res.status).toBe(201);
      expect(res.body.success).toBe(true);
      expect(res.body.user).toBeDefined();
      expect(res.body.user.email).toBe(mockUser.email);
      expect(res.body.accessToken).toBeDefined();
      
      const cookies = res.headers['set-cookie'] as unknown as string[] | undefined;
      expect(cookies).toBeDefined();
      const hasAccessTokenCookie = cookies?.some((c: string) => c.includes('access_token')) ?? false;
      const hasRefreshTokenCookie = cookies?.some((c: string) => c.includes('refresh_token')) ?? false;
      expect(hasAccessTokenCookie).toBe(true);
      expect(hasRefreshTokenCookie).toBe(true);
    });

    it('should fail registration with invalid input types', async () => {
      const res = await request(app)
        .post('/api/auth/register')
        .send({
          ...mockUser,
          email: 'invalid-email',
          age: 'not-a-number',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.errors).toBeDefined();
    });

    it('should not allow registering an already existing email', async () => {
      await request(app).post('/api/auth/register').send(mockUser);
      const res = await request(app).post('/api/auth/register').send(mockUser);

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Email already registered.');
    });
  });

  describe('POST /api/auth/login', () => {
    beforeEach(async () => {
      await request(app).post('/api/auth/register').send(mockUser);
    });

    it('should login successfully with correct credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: mockUser.email,
          password: mockUser.password,
        });

      expect(res.status).toBe(200);
      expect(res.body.success).toBe(true);
      expect(res.body.accessToken).toBeDefined();
    });

    it('should fail login with wrong credentials', async () => {
      const res = await request(app)
        .post('/api/auth/login')
        .send({
          email: mockUser.email,
          password: 'wrongpassword',
        });

      expect(res.status).toBe(400);
      expect(res.body.success).toBe(false);
      expect(res.body.message).toBe('Invalid credentials.');
    });
  });

  describe('GET /api/auth/me', () => {
    it('should fetch the profile of the currently logged in user', async () => {
      const registerRes = await request(app).post('/api/auth/register').send(mockUser);
      const token = registerRes.body.accessToken;

      const meRes = await request(app)
        .get('/api/auth/me')
        .set('Authorization', `Bearer ${token}`);

      expect(meRes.status).toBe(200);
      expect(meRes.body.success).toBe(true);
      expect(meRes.body.user.email).toBe(mockUser.email);
    });

    it('should block profile fetching without token', async () => {
      const meRes = await request(app).get('/api/auth/me');
      expect(meRes.status).toBe(401);
    });
  });
});
