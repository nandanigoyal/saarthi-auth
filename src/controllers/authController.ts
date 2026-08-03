import { Request, Response } from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import User from '../models/User';
import RefreshToken from '../models/RefreshToken';
import { sendMail } from '../utils/mailer';
import logger from '../utils/logger';
import { AuthenticatedRequest } from '../middleware/authMiddleware';

const ACCESS_SECRET = process.env.JWT_ACCESS_SECRET || 'supersecretaccesstokensecretkey12345!';
const REFRESH_SECRET = process.env.JWT_REFRESH_SECRET || 'supersecretrefreshtokensecretkey12345!';

// Helper to generate access & refresh tokens
const generateTokens = async (userId: string) => {
  const accessToken = jwt.sign({ id: userId }, ACCESS_SECRET, { expiresIn: '15m' });
  const refreshToken = jwt.sign(
    { id: userId, jti: crypto.randomBytes(16).toString('hex') },
    REFRESH_SECRET,
    { expiresIn: '7d' }
  );

  // Save refresh token to db
  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 7);

  await RefreshToken.create({
    user: userId,
    token: refreshToken,
    expiresAt,
  });

  return { accessToken, refreshToken };
};

// Set cookie helper
const setCookies = (res: Response, accessToken: string, refreshToken: string) => {
  // Hardcoded for cross-domain usage (Vercel -> Render)
  res.cookie('access_token', accessToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 15 * 60 * 1000, // 15 mins
  });

  res.cookie('refresh_token', refreshToken, {
    httpOnly: true,
    secure: true,
    sameSite: 'none',
    maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
  });
};

export const register = async (req: Request, res: Response) => {
  try {
    const { name, email, password, phone, age, city } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ success: false, message: 'Email already registered.' });
    }

    const verificationToken = crypto.randomBytes(32).toString('hex');

    const newUser = await User.create({
      name,
      email,
      password,
      phone,
      age,
      city,
      verificationToken,
    });

    // Send verification email (mock or real)
    const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
    const verifyUrl = `${clientUrl}/verify-email?token=${verificationToken}`;
    
    await sendMail(
      email,
      'Verify your Saarthi Account',
      `<h2>Welcome to Saarthi, ${name}!</h2><p>Please verify your account by clicking the link below:</p><a href="${verifyUrl}">Verify Email</a>`
    );

    const { accessToken, refreshToken } = await generateTokens(newUser._id.toString());
    setCookies(res, accessToken, refreshToken);

    return res.status(201).json({
      success: true,
      message: 'Registration successful. Verification email sent.',
      user: {
        id: newUser._id,
        name: newUser.name,
        email: newUser.email,
        phone: newUser.phone,
        age: newUser.age,
        city: newUser.city,
        role: newUser.role,
        isVerified: newUser.isVerified,
      },
      accessToken,
    });
  } catch (error: any) {
    logger.error('Registration error:', error);
    return res.status(500).json({ success: false, message: 'Server error during registration.' });
  }
};

export const login = async (req: Request, res: Response) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid credentials.' });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Invalid credentials.' });
    }

    const { accessToken, refreshToken } = await generateTokens(user._id.toString());
    setCookies(res, accessToken, refreshToken);

    return res.status(200).json({
      success: true,
      message: 'Login successful.',
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
        phone: user.phone,
        age: user.age,
        city: user.city,
        role: user.role,
        isVerified: user.isVerified,
      },
      accessToken,
    });
  } catch (error: any) {
    logger.error('Login error:', error);
    return res.status(500).json({ success: false, message: 'Server error during login.' });
  }
};

export const logout = async (req: Request, res: Response) => {
  try {
    const token = req.cookies.refresh_token || req.body.refreshToken;

    if (token) {
      // Mark token as revoked in db
      await RefreshToken.findOneAndUpdate({ token }, { isRevoked: true });
    }

    res.clearCookie('access_token');
    res.clearCookie('refresh_token');

    return res.status(200).json({ success: true, message: 'Logged out successfully.' });
  } catch (error: any) {
    logger.error('Logout error:', error);
    return res.status(500).json({ success: false, message: 'Server error during logout.' });
  }
};

export const refreshToken = async (req: Request, res: Response) => {
  try {
    const token = req.cookies.refresh_token || req.body.refreshToken;

    if (!token) {
      return res.status(401).json({ success: false, message: 'Refresh token required.' });
    }

    const decoded = jwt.verify(token, REFRESH_SECRET) as { id: string };
    
    const dbToken = await RefreshToken.findOne({ token, isRevoked: false });
    if (!dbToken || dbToken.expiresAt < new Date()) {
      return res.status(401).json({ success: false, message: 'Invalid or expired refresh token.' });
    }

    const user = await User.findById(decoded.id);
    if (!user) {
      return res.status(401).json({ success: false, message: 'User not found.' });
    }

    // Generate new access token
    const newAccessToken = jwt.sign({ id: user._id }, ACCESS_SECRET, { expiresIn: '15m' });
    
    // Refresh tokens rotation (optional): generate a new refresh token and revoke the old one
    const newRefreshToken = jwt.sign({ id: user._id }, REFRESH_SECRET, { expiresIn: '7d' });
    
    dbToken.isRevoked = true;
    await dbToken.save();

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7);
    await RefreshToken.create({
      user: user._id,
      token: newRefreshToken,
      expiresAt,
    });

    setCookies(res, newAccessToken, newRefreshToken);

    return res.status(200).json({
      success: true,
      accessToken: newAccessToken,
    });
  } catch (error: any) {
    logger.error('Refresh token error:', error);
    return res.status(401).json({ success: false, message: 'Invalid refresh token.' });
  }
};

export const verifyEmail = async (req: Request, res: Response) => {
  try {
    const { token } = req.body;

    const user = await User.findOne({ verificationToken: token });
    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired verification token.' });
    }

    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    return res.status(200).json({ success: true, message: 'Email verified successfully.' });
  } catch (error: any) {
    logger.error('Email verification error:', error);
    return res.status(500).json({ success: false, message: 'Server error during email verification.' });
  }
};

export const forgotPassword = async (req: Request, res: Response) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      // Don't leak if account exists
      return res.status(200).json({ success: true, message: 'If email exists, a reset link was sent.' });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    user.resetPasswordToken = resetToken;
    user.resetPasswordExpires = new Date(Date.now() + 3600000); // 1 hour
    await user.save();

    const clientUrl = process.env.CLIENT_URL || 'http://localhost:5173';
    const resetUrl = `${clientUrl}/reset-password?token=${resetToken}`;

    await sendMail(
      email,
      'Reset your Saarthi Password',
      `<h2>Password Reset Request</h2><p>You requested a password reset. Click below to reset your password:</p><a href="${resetUrl}">Reset Password</a>`
    );

    return res.status(200).json({ success: true, message: 'If email exists, a reset link was sent.' });
  } catch (error: any) {
    logger.error('Forgot password error:', error);
    return res.status(500).json({ success: false, message: 'Server error during password reset request.' });
  }
};

export const resetPassword = async (req: Request, res: Response) => {
  try {
    const { token, password } = req.body;

    const user = await User.findOne({
      resetPasswordToken: token,
      resetPasswordExpires: { $gt: new Date() },
    });

    if (!user) {
      return res.status(400).json({ success: false, message: 'Invalid or expired reset token.' });
    }

    user.password = password;
    user.resetPasswordToken = undefined;
    user.resetPasswordExpires = undefined;
    await user.save();

    return res.status(200).json({ success: true, message: 'Password reset successful.' });
  } catch (error: any) {
    logger.error('Reset password error:', error);
    return res.status(500).json({ success: false, message: 'Server error during password reset.' });
  }
};

export const changePassword = async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { currentPassword, newPassword } = req.body;
    const user = await User.findById(req.user?._id);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User not found.' });
    }

    const isMatch = await user.comparePassword(currentPassword);
    if (!isMatch) {
      return res.status(400).json({ success: false, message: 'Incorrect current password.' });
    }

    user.password = newPassword;
    await user.save();

    return res.status(200).json({ success: true, message: 'Password changed successfully.' });
  } catch (error: any) {
    logger.error('Change password error:', error);
    return res.status(500).json({ success: false, message: 'Server error during password change.' });
  }
};

export const getCurrentUser = async (req: AuthenticatedRequest, res: Response) => {
  try {
    return res.status(200).json({
      success: true,
      user: {
        id: req.user?._id,
        name: req.user?.name,
        email: req.user?.email,
        phone: req.user?.phone,
        age: req.user?.age,
        city: req.user?.city,
        role: req.user?.role,
        isVerified: req.user?.isVerified,
      },
    });
  } catch (error: any) {
    logger.error('Get current user error:', error);
    return res.status(500).json({ success: false, message: 'Server error fetching user profile.' });
  }
};
