# Saarthi Authentication Service (`saarthi-auth`)

This is the centralized authentication service for the Saarthi platform. It handles user registration, secure login, secure cookies, refresh token rotation, password resets, and user verification.

## Tech Stack
- **Framework**: Express.js with TypeScript
- **Database**: MongoDB (Mongoose ODM)
- **Security**: JSON Web Tokens (JWT), bcryptjs, Helmet, CORS, Express Rate Limit
- **Testing**: Jest & Supertest (leveraging MongoMemoryServer for in-memory DB testing)
- **Logging**: Winston logger & Morgan request logging

---

## Installation & Setup

1. **Environment Variables**:
   Create a `.env` file based on `.env.example`:
   ```bash
   cp .env.example .env
   ```

2. **Install Dependencies**:
   ```bash
   npm install
   ```

3. **Run Locally (Development Mode)**:
   ```bash
   npm run dev
   ```

4. **Build for Production**:
   ```bash
   npm run build
   ```

5. **Run Integration Tests**:
   ```bash
   npm test
   ```

---

## Centralized Authentication Integration Flow
To authenticate feature applications, retrieve the user state by invoking the `/api/auth/me` endpoint with the user's token or secure cookies.

- **Access Token Life**: 15 minutes (passed in Bearer Authorization header or cookie)
- **Refresh Token Life**: 7 days (httpOnly cookie, supports revocation and rotation)
