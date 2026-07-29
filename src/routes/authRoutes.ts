import { Router } from 'express';
import { body, validationResult } from 'express-validator';
import * as authController from '../controllers/authController';
import { authenticate } from '../middleware/authMiddleware';

const router = Router();

const validate = (req: any, res: any, next: any) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ success: false, errors: errors.array() });
  }
  next();
};

router.post(
  '/register',
  [
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
    body('phone').trim().notEmpty().withMessage('Phone number is required'),
    body('age').isInt({ min: 1 }).withMessage('Age must be a positive integer'),
    body('city').trim().notEmpty().withMessage('City is required'),
  ],
  validate,
  authController.register
);

router.post(
  '/login',
  [
    body('email').isEmail().withMessage('Please provide a valid email'),
    body('password').notEmpty().withMessage('Password is required'),
  ],
  validate,
  authController.login
);

router.post('/logout', authController.logout);

router.post('/refresh-token', authController.refreshToken);

router.post(
  '/verify-email',
  [body('token').notEmpty().withMessage('Verification token is required')],
  validate,
  authController.verifyEmail
);

router.post(
  '/forgot-password',
  [body('email').isEmail().withMessage('Please provide a valid email')],
  validate,
  authController.forgotPassword
);

router.post(
  '/reset-password',
  [
    body('token').notEmpty().withMessage('Reset token is required'),
    body('password').isLength({ min: 6 }).withMessage('Password must be at least 6 characters long'),
  ],
  validate,
  authController.resetPassword
);

router.post(
  '/change-password',
  authenticate,
  [
    body('currentPassword').notEmpty().withMessage('Current password is required'),
    body('newPassword').isLength({ min: 6 }).withMessage('New password must be at least 6 characters long'),
  ],
  validate,
  authController.changePassword
);

router.get('/me', authenticate, authController.getCurrentUser);

export default router;
