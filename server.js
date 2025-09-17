// backend/server.js

// 1. นำเข้า Environment Variables
require('dotenv').config();

// 2. นำเข้า Modules ที่จำเป็น
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const admin = require('firebase-admin');
// const User = require('./models/User'); // Commented out to use inline schema
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { Server } = require('socket.io');
const http = require('http');

// Login History Schema
const loginHistorySchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    action: { type: String, required: true }, // 'login', 'logout', 'password_changed', '2fa_enabled', etc.
    ipAddress: { type: String },
    userAgent: { type: String },
    location: { type: String },
    timestamp: { type: Date, default: Date.now }
});

const LoginHistory = mongoose.model('LoginHistory', loginHistorySchema);

// Active Session Schema
const activeSessionSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    sessionToken: { type: String, required: true },
    ipAddress: { type: String },
    userAgent: { type: String },
    location: { type: String },
    createdAt: { type: Date, default: Date.now },
    lastActivity: { type: Date, default: Date.now },
    isActive: { type: Boolean, default: true }
});

const ActiveSession = mongoose.model('ActiveSession', activeSessionSchema);

// 3. สร้าง Express App และ HTTP Server
const app = express();
const server = http.createServer(app);
const port = process.env.PORT || 5000;

// 3.1 Initialize Socket.IO
const io = new Server(server, {
    cors: {
        origin: ["http://localhost:3001", "http://localhost:3000"],
        methods: ["GET", "POST"],
        credentials: true
    }
});

// 4. Firebase Admin SDK Initialization
const serviceAccount = require('./chair-f440c-firebase-adminsdk-fbsvc-92d591e38e.json');
admin.initializeApp({
    credential: admin.credential.cert(serviceAccount)
});
console.log('Firebase Admin SDK initialized.');

// 5. Middleware
app.use(cors());
app.use(express.json());
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// 5.1. Email Configuration
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    },
    tls: {
        rejectUnauthorized: false
    }
});

// Test email configuration on startup
transporter.verify(function(error, success) {
    if (error) {
        console.log('Email configuration error:', error);
    } else {
        console.log('Email server is ready to send messages');
    }
});

// 6. เชื่อมต่อ MongoDB Database
const uri = process.env.MONGODB_URI;
mongoose.connect(uri)
    .then(() => console.log('MongoDB connected successfully!'))
    .catch(err => console.error('MongoDB connection error:', err));

const ClassroomSchema = new mongoose.Schema({
    // ... fields ที่มีอยู่แล้ว
    seatingPositions: {
        type: Object,
        default: {}
    },
    assignedUsers: {
        type: Map,
        of: {
            userName: String,
            userId: mongoose.Schema.Types.ObjectId,
            photoURL: String // สามารถเก็บ URL รูปภาพของผู้ใช้ได้
        },
        default: {}
    }
});

// 7. กำหนด User Schema และ Model สำหรับ MongoDB
const userSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, trim: true, lowercase: true },
    password: { type: String, select: false },
    displayName: { type: String },
    photoURL: { type: String },
    uid: { type: String, unique: true, sparse: true, default: null },
    createdClasses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Class' }],
    enrolledClasses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Class' }],
    pinnedClasses: [{ type: mongoose.Schema.Types.ObjectId, ref: 'Class' }], // เพิ่มโค้ดนี้
    resetPasswordToken: { type: String, select: false },
    resetPasswordExpires: { type: Date, select: false },
    twoFactorEnabled: { type: Boolean, default: false },
    twoFactorCode: { type: String, select: false },
    twoFactorExpires: { type: Date, select: false },
    loginOtpCode: { type: String, select: false },
    loginOtpExpires: { type: Date, select: false }
});
const User = mongoose.model('User', userSchema);

const classSchema = new mongoose.Schema({
    name: { type: String, required: true },
    subname: { type: String, default: 'General' },
    imageUrl: { type: String },
    bannerUrl: { type: String }, // Add bannerUrl to the schema
    color: { type: String, default: '#4CAF50' },
    classCode: { type: String, required: true, unique: true },
    creator: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }], // ✨ แก้ไข: เปลี่ยนกลับเป็น Array เพื่อรองรับ creator หลายคน
    participants: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User' }],
    isPublic: { type: Boolean, default: false }, // เพิ่มฟิลด์ isPublic
    allowSelfJoin: { type: Boolean, default: true }, // เพิ่มฟิลด์ allowSelfJoin
    seatingPositions: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    assignedUsers: {
        type: mongoose.Schema.Types.Mixed, // หรือจะใช้ Map ก็ได้
        default: {}
    },
    studentScores: {
        type: mongoose.Schema.Types.Mixed,
        default: {}
    },
    rows: { type: Number, default: 0 },
    cols: { type: Number, default: 0 },
});
const Class = mongoose.model('Class', classSchema);

// Socket.IO Connection Handling
io.on('connection', (socket) => {
    console.log('User connected:', socket.id);

    // Join classroom room
    socket.on('join-classroom', (data) => {
        const { classId, userId, userName } = data;
        socket.join(classId);
        console.log(`User ${userName} (${userId}) joined classroom ${classId}`);
    });

    // Handle score updates
    socket.on('update-score', (data) => {
        console.log('Score update received:', data);
        const { classId, studentId, newScore, presetName, studentName, updatedBy, timestamp } = data;
        
        // Emit to all users in the classroom
        socket.to(classId).emit('score-updated', {
            studentId,
            newScore,
            presetName,
            studentName,
            updatedBy,
            timestamp
        });
    });

    // Handle broadcast score updates
    socket.on('broadcast-score-update', (data) => {
        console.log('Broadcasting score update:', data);
        const { classId } = data;
        
        // Broadcast to all users in the classroom including sender
        io.to(classId).emit('broadcast-score-update', data);
    });

    // Handle chair seating updates
    socket.on('chair-seating-update', (data) => {
        console.log('Chair seating update received:', data);
        const { classId, chairId, assignedUsers, action, userName, updatedBy, timestamp } = data;
        
        // Emit to all users in the classroom except sender
        socket.to(classId).emit('chair-seating-updated', {
            chairId,
            assignedUsers,
            action,
            userName,
            updatedBy,
            timestamp
        });
    });

    // Handle chair movement updates
    socket.on('chair-movement-update', (data) => {
        console.log('Chair movement update received:', data);
        const { classId, chairPositions, movedChairId, updatedBy, timestamp } = data;
        
        // Emit to all users in the classroom except sender
        socket.to(classId).emit('chair-moved', {
            chairPositions,
            movedChairId,
            updatedBy,
            timestamp
        });
    });

    socket.on('disconnect', () => {
        console.log('User disconnected:', socket.id);
    });
});

// 9. Middleware สำหรับตรวจสอบสิทธิ์
const authMiddleware = async (req, res, next) => {
    const token = req.header('x-auth-token');
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.user.id);
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }
        req.user = user;
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid' });
    }
};

// ** File Upload Middleware for Profile Photo **
const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = path.join(__dirname, 'uploads', 'profile_photos');
        fs.mkdirSync(uploadPath, { recursive: true });
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        cb(null, req.user._id + '-' + Date.now() + path.extname(file.originalname));
    }
});
const upload = multer({
    storage: storage,
    fileFilter: function (req, file, cb) {
        const filetypes = /jpeg|jpg|png|gif/;
        const mimetype = filetypes.test(file.mimetype);
        const extname = filetypes.test(path.extname(file.originalname).toLowerCase());

        if (mimetype && extname) {
            return cb(null, true);
        }
        cb("Error: File upload only supports the following filetypes - " + filetypes);
    }
}).single('profileImage');

// 10. API Routes

// ** Google Login Verification (ใช้ Firebase Admin)**
app.post('/api/auth/google-login-verify', async (req, res) => {
    console.log('Google login verification request received');
    const { idToken } = req.body;
    
    if (!idToken) {
        console.log('No ID token provided');
        return res.status(400).json({ msg: 'ID token is required' });
    }

    try {
        console.log('Verifying Google ID token...');
        const decodedToken = await admin.auth().verifyIdToken(idToken);
        const { uid, email, picture, name } = decodedToken;
        console.log('Google token verified for user:', email);

        let user = await User.findOne({ email });
        let isNewUser = false;

        if (!user) {
            console.log('Creating new user from Google account:', email);
            isNewUser = true;
            user = new User({
                email,
                displayName: name || email.split('@')[0],
                photoURL: picture || '',
                uid
            });
            await user.save();
            console.log('New Google user created:', user._id);
        } else {
            console.log('Existing user found, updating Google info if needed');
            let needsUpdate = false;
            
            if (!user.uid) {
                user.uid = uid;
                needsUpdate = true;
            }
            // Only update photoURL from Google if user doesn't have a custom photo
            // Custom photos start with '/uploads/' while Google photos are full URLs
            if (picture && (!user.photoURL || user.photoURL === '' || user.photoURL.startsWith('https://'))) {
                user.photoURL = picture;
                needsUpdate = true;
            }
            if (name && user.displayName !== name) {
                user.displayName = name;
                needsUpdate = true;
            }
            
            if (needsUpdate) {
                await user.save();
                console.log('User Google info updated');
            }
        }

        const payload = {
            user: {
                id: user.id,
                email: user.email,
                displayName: user.displayName,
                photoURL: user.photoURL,
                uid: user.uid
            },
        };

        console.log('Generating JWT token for Google user...');
        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '1h' },
            (err, token) => {
                if (err) {
                    console.error('JWT signing error for Google user:', err);
                    throw err;
                }
                console.log('Google authentication successful');
                res.json({ 
                    token, 
                    user: payload.user,
                    isNewUser 
                });
            }
        );
    } catch (error) {
        console.error("Error verifying Google token:", error);
        if (error.code === 'auth/id-token-expired') {
            res.status(401).json({ msg: 'Google token has expired. Please sign in again.' });
        } else if (error.code === 'auth/invalid-id-token') {
            res.status(401).json({ msg: 'Invalid Google token.' });
        } else {
            res.status(500).json({ msg: 'Server error during Google authentication', error: error.message });
        }
    }
});

// ** Manual Register User **
app.post('/api/auth/register', async (req, res) => {
    console.log('Registration request received:', req.body);
    const { email, password, displayName } = req.body;

    // Input validation
    if (!email || !password) {
        console.log('Missing required fields:', { email: !!email, password: !!password });
        return res.status(400).json({ msg: 'Email and password are required.' });
    }

    // Enhanced password validation
    if (password.length < 8) {
        console.log('Password too short');
        return res.status(400).json({ msg: 'Password must be at least 8 characters long.' });
    }

    // Check password strength requirements
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    const strengthScore = [hasUppercase, hasLowercase, hasNumber, hasSpecial].filter(Boolean).length;
    
    if (strengthScore < 3) {
        console.log('Password too weak, score:', strengthScore);
        return res.status(400).json({ 
            msg: 'Password must contain at least 3 of the following: uppercase letter, lowercase letter, number, special character.' 
        });
    }

    try {
        const normalizedEmail = email.toLowerCase().trim();
        console.log('Checking if user exists with email:', normalizedEmail);
        
        // Check both exact match and case-insensitive match
        let user = await User.findOne({ 
            email: { $regex: new RegExp(`^${normalizedEmail.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, 'i') }
        });
        
        if (user) {
            console.log('User already exists with email:', normalizedEmail, 'Found user:', user.email);
            return res.status(400).json({ msg: 'User already exists with this email.' });
        }

        console.log('No existing user found, creating new user...');
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        user = new User({
            email: normalizedEmail,
            password: hashedPassword,
            displayName: displayName || normalizedEmail.split('@')[0],
            photoURL: null,
            uid: new mongoose.Types.ObjectId().toString()
        });

        console.log('Saving user to database...');
        await user.save();
        console.log('User saved successfully:', user._id);

        const payload = {
            user: {
                id: user.id,
                email: user.email,
                displayName: user.displayName,
                photoURL: user.photoURL,
                uid: user.uid
            },
        };

        console.log('Generating JWT token...');
        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '1h' },
            (err, token) => {
                if (err) {
                    console.error('JWT signing error:', err);
                    throw err;
                }
                console.log('Registration successful, sending response');
                res.status(201).json({
                    msg: 'User registered successfully!',
                    token,
                    user: payload.user
                });
            }
        );
    } catch (err) {
        console.error('Registration error:', err);
        if (err.code === 11000) {
            // Check which field caused the duplicate
            if (err.keyPattern && err.keyPattern.email) {
                return res.status(400).json({ msg: 'User already exists with this email.' });
            } else if (err.keyPattern && err.keyPattern.uid) {
                return res.status(500).json({ msg: 'Database constraint error. Please try again.' });
            }
            return res.status(400).json({ msg: 'User already exists.' });
        }
        res.status(500).json({ msg: 'Server error during registration', error: err.message });
    }
});

// ** Manual Login User **
app.post('/api/auth/login', async (req, res) => {
    const { email, password, otpCode } = req.body;

    try {
        let user = await User.findOne({ email }).select('+password +twoFactorEnabled +loginOtpCode +loginOtpExpires');
        if (!user) {
            return res.status(400).json({ msg: 'Invalid Credentials.' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Invalid Credentials.' });
        }

        // Check if 2FA is enabled
        if (user.twoFactorEnabled) {
            // If OTP code is not provided, send OTP and require verification
            if (!otpCode) {
                // Generate 6-digit OTP
                const otp = Math.floor(100000 + Math.random() * 900000).toString();
                const otpExpires = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

                // Save OTP to user
                await User.findByIdAndUpdate(user._id, {
                    loginOtpCode: otp,
                    loginOtpExpires: otpExpires
                });

                // Send OTP email
                const mailOptions = {
                    from: process.env.EMAIL_USER,
                    to: user.email,
                    subject: 'Chair App - Login Verification Code',
                    html: `
                        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                            <h2 style="color: #1a73e8;">Login Verification Required</h2>
                            <p>Your login verification code is:</p>
                            <div style="background: #f8f9fa; padding: 20px; text-align: center; margin: 20px 0; border-radius: 8px;">
                                <h1 style="color: #1a73e8; font-size: 32px; margin: 0; letter-spacing: 5px;">${otp}</h1>
                            </div>
                            <p>This code will expire in 10 minutes.</p>
                            <p>If you didn't request this login, please ignore this email.</p>
                        </div>
                    `
                };

                await transporter.sendMail(mailOptions);

                return res.json({ 
                    requiresOtp: true, 
                    message: 'OTP sent to your email. Please verify to complete login.',
                    tempUserId: user._id
                });
            }

            // If OTP code is provided, verify it
            if (otpCode) {
                if (!user.loginOtpCode || !user.loginOtpExpires) {
                    return res.status(400).json({ msg: 'No OTP found. Please request a new one.' });
                }

                if (new Date() > user.loginOtpExpires) {
                    return res.status(400).json({ msg: 'OTP has expired. Please request a new one.' });
                }

                if (otpCode !== user.loginOtpCode) {
                    return res.status(400).json({ msg: 'Invalid OTP code.' });
                }

                // Clear OTP after successful verification
                await User.findByIdAndUpdate(user._id, {
                    $unset: { loginOtpCode: 1, loginOtpExpires: 1 }
                });
            }
        }

        // Log successful login
        await LoginHistory.create({
            userId: user._id,
            action: 'login',
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent')
        });

        const payload = {
            user: {
                id: user.id,
                email: user.email,
                displayName: user.displayName,
                photoURL: user.photoURL,
                uid: user.uid,
                twoFactorEnabled: user.twoFactorEnabled
            },
        };

        jwt.sign(
            payload,
            process.env.JWT_SECRET,
            { expiresIn: '1h' },
            (err, token) => {
                if (err) throw err;
                res.json({ token, user: payload.user });
            }
        );
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// ** Forgot Password Endpoint **
app.post('/api/auth/forgot-password', async (req, res) => {
    console.log('Forgot password request received:', req.body);
    const { email } = req.body;

    // Input validation
    if (!email) {
        console.log('Missing email field');
        return res.status(400).json({ msg: 'Email is required.' });
    }

    try {
        const normalizedEmail = email.toLowerCase().trim();
        console.log('Looking for user with email:', normalizedEmail);
        
        const user = await User.findOne({ email: normalizedEmail }).select('+resetPasswordToken +resetPasswordExpires');
        
        if (!user) {
            console.log('User not found with email:', normalizedEmail);
            // Don't reveal if user exists or not for security
            return res.json({ msg: 'If an account with that email exists, we have sent a password reset link.' });
        }

        console.log('User found, generating reset token...');
        
        // Generate reset token
        const resetToken = crypto.randomBytes(32).toString('hex');
        const resetTokenHash = crypto.createHash('sha256').update(resetToken).digest('hex');
        
        // Set token and expiration (1 hour)
        user.resetPasswordToken = resetTokenHash;
        user.resetPasswordExpires = Date.now() + 60 * 60 * 1000; // 1 hour
        await user.save();

        console.log('Reset token saved, sending email...');

        // Create reset URL
        const resetURL = `${process.env.CLIENT_URL || 'http://localhost:3000'}/reset-password/${resetToken}`;

        // Email options
        const mailOptions = {
            from: process.env.EMAIL_USER,
            to: user.email,
            subject: 'Password Reset Request - Chair App',
            html: `
                <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                    <h2 style="color: #4CAF50;">Password Reset Request</h2>
                    <p>Hello ${user.displayName || 'User'},</p>
                    <p>You have requested to reset your password for your Chair App account.</p>
                    <p>Please click the button below to reset your password:</p>
                    <div style="text-align: center; margin: 30px 0;">
                        <a href="${resetURL}" 
                           style="background-color: #4CAF50; color: white; padding: 12px 30px; 
                                  text-decoration: none; border-radius: 5px; display: inline-block;">
                            Reset Password
                        </a>
                    </div>
                    <p>Or copy and paste this link in your browser:</p>
                    <p style="word-break: break-all; color: #666;">${resetURL}</p>
                    <p><strong>This link will expire in 1 hour.</strong></p>
                    <p>If you did not request this password reset, please ignore this email.</p>
                    <hr style="margin: 30px 0; border: none; border-top: 1px solid #eee;">
                    <p style="color: #666; font-size: 12px;">Chair App Team</p>
                </div>
            `
        };

        // Send email
        try {
            await transporter.sendMail(mailOptions);
            console.log('Password reset email sent successfully to:', user.email);
        } catch (emailError) {
            console.error('Email sending error:', emailError);
            throw new Error(`Email sending failed: ${emailError.message}`);
        }

        res.json({ msg: 'If an account with that email exists, we have sent a password reset link.' });
    } catch (err) {
        console.error('Forgot password error:', err);
        
        // More specific error messages for debugging
        if (err.message.includes('Email sending failed')) {
            res.status(500).json({ 
                msg: 'Failed to send reset email. Please check email configuration.', 
                error: err.message 
            });
        } else {
            res.status(500).json({ 
                msg: 'Server error during password reset request', 
                error: err.message 
            });
        }
    }
});

// ** Reset Password Endpoint **
app.post('/api/auth/reset-password/:token', async (req, res) => {
    console.log('Reset password request received');
    const { token } = req.params;
    const { password } = req.body;

    // Input validation
    if (!password) {
        console.log('Missing password field');
        return res.status(400).json({ msg: 'Password is required.' });
    }

    // Enhanced password validation
    if (password.length < 8) {
        console.log('Password too short');
        return res.status(400).json({ msg: 'Password must be at least 8 characters long.' });
    }

    // Check password strength requirements
    const hasUppercase = /[A-Z]/.test(password);
    const hasLowercase = /[a-z]/.test(password);
    const hasNumber = /\d/.test(password);
    const hasSpecial = /[!@#$%^&*(),.?":{}|<>]/.test(password);
    
    const strengthScore = [hasUppercase, hasLowercase, hasNumber, hasSpecial].filter(Boolean).length;
    
    if (strengthScore < 3) {
        console.log('Password too weak, score:', strengthScore);
        return res.status(400).json({ 
            msg: 'Password must contain at least 3 of the following: uppercase letter, lowercase letter, number, special character.' 
        });
    }

    try {
        console.log('Hashing reset token for lookup...');
        
        // Hash the token to compare with stored hash
        const resetTokenHash = crypto.createHash('sha256').update(token).digest('hex');
        
        // Find user with valid reset token
        const user = await User.findOne({
            resetPasswordToken: resetTokenHash,
            resetPasswordExpires: { $gt: Date.now() }
        }).select('+password +resetPasswordToken +resetPasswordExpires');

        if (!user) {
            console.log('Invalid or expired reset token');
            return res.status(400).json({ msg: 'Password reset token is invalid or has expired.' });
        }

        console.log('Valid reset token found, updating password...');

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        // Update password and clear reset token fields
        user.password = hashedPassword;
        user.resetPasswordToken = undefined;
        user.resetPasswordExpires = undefined;
        await user.save();

        console.log('Password updated successfully');

        res.json({ msg: 'Password has been reset successfully. You can now login with your new password.' });
    } catch (err) {
        console.error('Reset password error:', err);
        res.status(500).json({ msg: 'Server error during password reset', error: err.message });
    }
});


// Change password endpoint
app.put('/api/auth/change-password', authMiddleware, async (req, res) => {
    try {
        const { currentPassword, newPassword } = req.body;
        const userId = req.user.id;

        if (!currentPassword || !newPassword) {
            return res.status(400).json({ msg: 'Current password and new password are required' });
        }

        if (newPassword.length < 6) {
            return res.status(400).json({ msg: 'New password must be at least 6 characters long' });
        }

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        // Verify current password
        const isMatch = await bcrypt.compare(currentPassword, user.password);
        if (!isMatch) {
            return res.status(400).json({ msg: 'Current password is incorrect' });
        }

        // Hash new password
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(newPassword, salt);

        // Update password
        await User.findByIdAndUpdate(userId, { password: hashedPassword });

        // Log the password change
        await LoginHistory.create({
            userId: userId,
            action: 'password_changed',
            ipAddress: req.ip || req.connection.remoteAddress,
            userAgent: req.get('User-Agent'),
            timestamp: new Date()
        });

        res.json({ msg: 'Password changed successfully' });

    } catch (error) {
        console.error('Change password error:', error);
        res.status(500).json({ msg: 'Server error while changing password' });
    }
});

// Enable/Disable Two-Factor Authentication
app.post('/api/auth/2fa/toggle', authMiddleware, async (req, res) => {
    try {
        const { enable } = req.body;
        const userId = req.user.id;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        if (enable) {
            // Generate and send 2FA code via email
            const code = Math.floor(100000 + Math.random() * 900000).toString();
            const expiresAt = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes

            await User.findByIdAndUpdate(userId, {
                twoFactorEnabled: true,
                twoFactorCode: code,
                twoFactorExpires: expiresAt
            });

            // Send email with 2FA code
            const mailOptions = {
                from: process.env.EMAIL_USER,
                to: user.email,
                subject: 'Two-Factor Authentication Setup - Chair App',
                html: `
                    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
                        <h2 style="color: #4CAF50;">Two-Factor Authentication Setup</h2>
                        <p>Hello ${user.displayName},</p>
                        <p>You have enabled Two-Factor Authentication for your Chair App account.</p>
                        <div style="background-color: #f5f5f5; padding: 20px; border-radius: 5px; text-align: center; margin: 20px 0;">
                            <h3 style="margin: 0; color: #333;">Your verification code:</h3>
                            <h1 style="color: #4CAF50; font-size: 32px; margin: 10px 0; letter-spacing: 5px;">${code}</h1>
                            <p style="color: #666; margin: 0;">This code will expire in 10 minutes</p>
                        </div>
                        <p>If you didn't request this, please contact support immediately.</p>
                        <p>Best regards,<br>Chair App Team</p>
                    </div>
                `
            };

            await transporter.sendMail(mailOptions);
            res.json({ msg: 'Two-Factor Authentication enabled. Check your email for verification code.' });

        } else {
            await User.findByIdAndUpdate(userId, {
                twoFactorEnabled: false,
                twoFactorCode: null,
                twoFactorExpires: null
            });
            res.json({ msg: 'Two-Factor Authentication disabled successfully' });
        }

    } catch (error) {
        console.error('2FA toggle error:', error);
        res.status(500).json({ msg: 'Server error while updating 2FA settings' });
    }
});

// Verify 2FA code
app.post('/api/auth/2fa/verify', authMiddleware, async (req, res) => {
    try {
        const { code } = req.body;
        const userId = req.user.id;

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        if (!user.twoFactorCode || user.twoFactorExpires < new Date()) {
            return res.status(400).json({ msg: 'Verification code has expired' });
        }

        if (user.twoFactorCode !== code) {
            return res.status(400).json({ msg: 'Invalid verification code' });
        }

        // Clear the verification code
        await User.findByIdAndUpdate(userId, {
            twoFactorCode: null,
            twoFactorExpires: null
        });

        res.json({ msg: 'Two-Factor Authentication verified successfully' });

    } catch (error) {
        console.error('2FA verify error:', error);
        res.status(500).json({ msg: 'Server error while verifying 2FA code' });
    }
});

// Get login history
app.get('/api/auth/login-history', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const history = await LoginHistory.find({ userId })
            .sort({ timestamp: -1 })
            .skip(skip)
            .limit(limit);

        const total = await LoginHistory.countDocuments({ userId });

        res.json({
            history,
            pagination: {
                current: page,
                total: Math.ceil(total / limit),
                hasNext: skip + limit < total,
                hasPrev: page > 1
            }
        });

    } catch (error) {
        console.error('Login history error:', error);
        res.status(500).json({ msg: 'Server error while fetching login history' });
    }
});

// Get active sessions
app.get('/api/auth/active-sessions', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;

        const sessions = await ActiveSession.find({ userId })
            .sort({ lastActivity: -1 });

        res.json({ sessions });

    } catch (error) {
        console.error('Active sessions error:', error);
        res.status(500).json({ msg: 'Server error while fetching active sessions' });
    }
});

// Terminate session
app.delete('/api/auth/sessions/:sessionId', authMiddleware, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const userId = req.user.id;

        const session = await ActiveSession.findOne({ _id: sessionId, userId });
        if (!session) {
            return res.status(404).json({ msg: 'Session not found' });
        }

        await ActiveSession.findByIdAndDelete(sessionId);
        res.json({ msg: 'Session terminated successfully' });

    } catch (error) {
        console.error('Terminate session error:', error);
        res.status(500).json({ msg: 'Server error while terminating session' });
    }
});

// Update user profile information
app.put('/api/auth/profile/update', authMiddleware, async (req, res) => {
    try {
        const userId = req.user.id;
        const updateData = req.body;

        // Remove sensitive fields that shouldn't be updated via this endpoint
        delete updateData.email;
        delete updateData.password;
        delete updateData._id;
        delete updateData.uid;

        console.log('Updating user profile:', userId, updateData);

        const updatedUser = await User.findByIdAndUpdate(
            userId,
            { $set: updateData },
            { new: true, runValidators: true }
        ).select('-password');

        if (!updatedUser) {
            return res.status(404).json({ msg: 'User not found' });
        }

        res.json({
            msg: 'Profile updated successfully',
            user: updatedUser
        });

    } catch (error) {
        console.error('Profile update error:', error);
        res.status(500).json({ msg: 'Server error while updating profile' });
    }
});

app.post('/api/auth/profile/update-photo', authMiddleware, (req, res) => {
    upload(req, res, async (err) => {
        if (err) {
            console.error("Upload error:", err);
            if (err && typeof err === 'object' && err.message) {
                 return res.status(400).json({ msg: err.message });
            } else {
                 return res.status(400).json({ msg: err.toString() });
            }
        }
        if (!req.file) {
            return res.status(400).json({ msg: 'No file uploaded.' });
        }

        try {
            const user = req.user;
            
            // ลบรูปเก่าาก่อนอัปโหลดรูปใหม่
            // This part is the key fix. It checks if a user has a photoURL and deletes the old file.
            if (user.photoURL) {
                const oldPhotoPath = path.join(__dirname, user.photoURL);
                // Check if the file exists before trying to delete it
                if (fs.existsSync(oldPhotoPath)) {
                    fs.unlinkSync(oldPhotoPath);
                }
            }

            const newPhotoURL = `/uploads/profile_photos/${req.file.filename}`;
            user.photoURL = newPhotoURL;
            await user.save();

            res.json({
                msg: 'Profile photo updated successfully!',
                user: {
                    id: user._id,
                    email: user.email,
                    displayName: user.displayName,
                    photoURL: newPhotoURL,
                    uid: user.uid,
                }
            });
        } catch (error) {
            console.error("Error updating photo URL:", error);
            res.status(500).send('Server error');
        }
    });
});

// ** Route for Deleting Profile Photo **
app.delete('/api/auth/profile/delete-photo', authMiddleware, async (req, res) => {
    try {
        const user = req.user;

        if (user.photoURL) {
            const photoPath = path.join(__dirname, user.photoURL);
            if (fs.existsSync(photoPath)) {
                fs.unlinkSync(photoPath);
            }
            user.photoURL = null; // ตั้งค่า photoURL เป็น null
            await user.save();
        }

        res.json({
            msg: 'Profile photo deleted successfully!',
            user: {
                id: user._id,
                email: user.email,
                displayName: user.displayName,
                photoURL: null, // ส่งค่า photoURL เป็น null กลับไป
                uid: user.uid,
            }
        });
    } catch (error) {
        console.error("Error deleting profile photo:", error);
        res.status(500).send('Server error');
    }
});
// ** เพิ่มโค้ดนี้: Route สำหรับปักหมุด/ถอดหมุดห้องเรียน **
app.post('/api/users/pin-class', authMiddleware, async (req, res) => {
    const { classId } = req.body;
    const userId = req.user._id;

    try {
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ msg: 'User not found.' });
        }

        const classIndex = user.pinnedClasses.indexOf(classId);
        let updatedUser;
        if (classIndex > -1) {
            // Class is already pinned, so unpin it
            user.pinnedClasses.splice(classIndex, 1);
            updatedUser = await user.save();
        } else {
            // Class is not pinned, so pin it
            user.pinnedClasses.push(classId);
            updatedUser = await user.save();
        }

        res.json({
            msg: `Class ${classIndex > -1 ? 'unpinned' : 'pinned'} successfully!`,
            user: updatedUser
        });

    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Route สำหรับการปักหมุด/ถอนปักหมุดห้องเรียน
app.post('/api/classrooms/:classId/toggle-pin', authMiddleware, async (req, res) => {
    try {
        const userId = req.user._id;
        const { classId } = req.params;
        const user = await User.findById(userId);

        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }

        const isPinned = user.pinnedClasses.includes(classId);

        if (isPinned) {
            user.pinnedClasses.pull(classId);
        } else {
            user.pinnedClasses.push(classId);
        }

        await user.save();
        const updatedUser = {
            id: user._id,
            email: user.email,
            displayName: user.displayName,
            photoURL: user.photoURL,
            uid: user.uid,
            pinnedClasses: user.pinnedClasses,
        };

        res.status(200).json({ msg: 'Pinned status updated successfully!', user: updatedUser });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.get('/api/classrooms/:id', authMiddleware, async (req, res) => {
    try {
        const userId = req.user._id;
        const classroom = await Class.findById(req.params.id)
            .populate('creator', 'displayName photoURL _id')
            .populate('participants', 'displayName photoURL');

        if (!classroom) {
            return res.status(404).json({ msg: 'Classroom not found' });
        }

        // ตรวจสอบสิทธิ์การเข้าถึง
        const isCreator = classroom.creator.some(creator => creator._id.toString() === userId.toString());
        const isParticipant = classroom.participants.some(participant => participant._id.toString() === userId.toString());
        const isMember = isCreator || isParticipant;

        // ถ้าเป็น public classroom และผู้ใช้ยังไม่ได้เป็นสมาชิก
        if (classroom.isPublic && !isMember) {
            // เพิ่มผู้ใช้เป็น participant อัตโนมัติ
            classroom.participants.push(userId);
            await classroom.save();
            
            // อัพเดท user's enrolledClasses
            await User.findByIdAndUpdate(userId, {
                $addToSet: { enrolledClasses: classroom._id }
            });

            // Populate ข้อมูลใหม่หลังจากเพิ่มสมาชิก
            const updatedClassroom = await Class.findById(req.params.id)
                .populate('creator', 'displayName photoURL _id')
                .populate('participants', 'displayName photoURL');
            
            return res.json(updatedClassroom);
        }

        // ถ้าเป็น private classroom และไม่ใช่สมาชิก
        if (!classroom.isPublic && !isMember) {
            return res.status(403).json({ 
                msg: 'Access denied. This classroom is private and requires an invitation.',
                requiresInvitation: true 
            });
        }

        // ถ้าเป็นสมาชิกแล้ว ให้ return ข้อมูลปกติ
        console.log('Returning classroom with scores:', classroom.studentScores);
        res.json(classroom);
    } catch (err) {
        console.error(err.message);
        if (err.kind === 'ObjectId') {
            return res.status(404).json({ msg: 'Classroom not found' });
        }
        res.status(500).send('Server Error');
    }
});

// Get authenticated user's profile
app.get('/api/auth/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.user._id);
        if (!user) {
            return res.status(404).json({ msg: 'User not found' });
        }
        res.json({
            id: user._id,
            email: user.email,
            displayName: user.displayName,
            photoURL: user.photoURL || null,
            uid: user.uid,
            createdClasses: user.createdClasses, // เพิ่มโค้ดนี้
            enrolledClasses: user.enrolledClasses, // เพิ่มโค้ดนี้
            pinnedClasses: user.pinnedClasses // เพิ่มโค้ดนี้
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Route สำหรับดึงห้องเรียนที่ผู้ใช้สร้างและเข้าร่วม
app.get('/api/classrooms', authMiddleware, async (req, res) => {
    try {
        const userId = req.user._id;
        const classrooms = await Class.find({
            $or: [
                { creator: userId },
                { participants: userId }
            ]
        }).populate('creator', 'displayName photoURL _id');
        res.json(classrooms);
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.post('/api/classrooms/create', authMiddleware, async (req, res) => {
    // ✨ รับ rows, cols, และ seatingPositions จาก req.body
    const { name, subname, imageUrl, color, rows, cols, seatingPositions } = req.body;
    const userId = req.user._id;

    try {
        const classCode = Math.random().toString(36).substring(2, 8).toUpperCase();

        const newClass = new Class({
            name,
            subname,
            imageUrl,
            color, // creator is now an array
            creator: [userId], // ✨ แก้ไข: กำหนด creator เป็น Array
            participants: [userId],
            classCode,
            // ✨ บันทึกค่าใหม่ลงใน object
            rows,
            cols,
            seatingPositions
        });

        await newClass.save();

        await User.findByIdAndUpdate(userId, { $push: { createdClasses: newClass._id, enrolledClasses: newClass._id } });

        res.status(201).json({
            msg: 'Class created successfully!',
            class: newClass
        });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

// Route สำหรับเข้าร่วมห้องเรียนด้วยรหัส
app.post('/api/classrooms/join', authMiddleware, async (req, res) => {
    const { classCode } = req.body;
    const userId = req.user._id;

    try {
        const classToJoin = await Class.findOne({ classCode });

        if (!classToJoin) {
            return res.status(404).json({ msg: 'Invalid class code. Class not found.' });
        }

        if (classToJoin.participants.includes(userId)) {
            return res.status(400).json({ msg: 'You are already a participant in this class.' });
        }

        classToJoin.participants.push(userId);
        await classToJoin.save();
        await User.findByIdAndUpdate(userId, { $push: { enrolledClasses: classToJoin._id } });

        res.status(200).json({ msg: 'Joined class successfully!', class: classToJoin });
    } catch (err) {
        console.error(err.message);
        res.status(500).send('Server error');
    }
});

app.put('/api/classrooms/:classId/seating', authMiddleware, async (req, res) => {
    const { classId } = req.params;
    const { seatingPositions, assignedUsers, studentScores } = req.body;
    try {
        console.log('Seating update request:', { seatingPositions, assignedUsers, studentScores });
        
        const updateObj = {};
        if (seatingPositions) updateObj.seatingPositions = seatingPositions;
        if (assignedUsers) updateObj.assignedUsers = assignedUsers;
        if (studentScores) updateObj.studentScores = studentScores;
        
        console.log('Update object:', updateObj);
        
        const classroom = await Class.findByIdAndUpdate(classId, updateObj, { new: true });
        if (!classroom) {
            return res.status(404).json({ msg: 'Classroom not found' });
        }
        
        console.log('Updated classroom scores:', classroom.studentScores);
        
        res.json({ 
            msg: 'Seating positions updated', 
            seatingPositions: classroom.seatingPositions, 
            assignedUsers: classroom.assignedUsers,
            studentScores: classroom.studentScores
        });
    } catch (err) {
        console.error('Error updating seating positions:', err);
        res.status(500).send('Server error');
    }
});

// Route สำหรับออกจากห้องเรียน
app.post('/api/classrooms/:classId/leave', authMiddleware, async (req, res) => {
    const { classId } = req.params;
    const userId = req.user._id;

    try {
        const classroom = await Class.findById(classId);
        if (!classroom) {
            return res.status(404).json({ msg: 'Classroom not found' });
        }

        // ✨ แก้ไข: ตรวจสอบว่าผู้ใช้เป็น creator หรือไม่
        const isCreator = classroom.creator.map(id => id.toString()).includes(userId.toString());

        // ถ้า user เป็น creator
        if (isCreator) {
            // ✨ แก้ไข: Logic สำหรับ creator หลายคน
            if (classroom.creator.length > 1) {
                // ถ้ามี creator มากกว่า 1 คน ให้ออกจากรายชื่อ creator และ participant
                classroom.creator = classroom.creator.filter(id => id.toString() !== userId.toString());
                classroom.participants = classroom.participants.filter(id => id.toString() !== userId.toString());
                await classroom.save();
                await User.findByIdAndUpdate(userId, { $pull: { createdClasses: classId, enrolledClasses: classId, pinnedClasses: classId } });
                return res.json({ msg: 'You have left your creator role.' });
            } else {
                // ถ้าเป็น creator คนเดียว ให้ลบห้องเรียน
                try {
                    await Class.findByIdAndDelete(classId);
                    // ลบ classId ออกจาก createdClasses, enrolledClasses, pinnedClasses ของ user ทุกคน
                    await User.updateMany({}, { $pull: { createdClasses: classId, enrolledClasses: classId, pinnedClasses: classId } });
                    return res.json({ msg: 'Classroom deleted as you were the sole creator.' });
                } catch (deleteErr) {
                    console.error('Error deleting classroom:', deleteErr);
                    return res.status(500).send('Server error during classroom deletion.');
                        }
            }
        }

        // ถ้าไม่ใช่ creator ให้ลบตัวเองออกจาก participants/enrolledClasses/pinnedClasses
        await Class.findByIdAndUpdate(classId, {
            $pull: { participants: userId },
            // ไม่จำเป็นต้อง markModified 'assignedUsers' ที่นี่ เพราะจะทำด้านล่าง
        });

        // ลบ assignedUsers ที่ user เคยนั่ง (ถ้ามี)
        if (classroom.assignedUsers) {
            let changed = false;
            for (const seat in classroom.assignedUsers) {
                if (classroom.assignedUsers[seat]?.userId?.toString() === userId.toString()) {
                    delete classroom.assignedUsers[seat];
                    changed = true;
                }
            }
            if (changed) {
                // Mongoose maps don't track deletes, so we need to mark it as modified.
                classroom.markModified('assignedUsers');
                await classroom.save();
            }
        }

        await User.findByIdAndUpdate(userId, {
            $pull: {
                enrolledClasses: classId,
                pinnedClasses: classId
            }
        });

        res.json({ msg: 'Successfully left the classroom.' });
    } catch (err) {
        console.error('Error leaving classroom:', err);
        res.status(500).send('Server error');
    }
});

app.put('/api/classrooms/:classId/kick', authMiddleware, async (req, res) => {
    const { classId } = req.params;
    const { userId } = req.body;
    try {
        const classroom = await Class.findById(classId);
        if (!classroom) return res.status(404).json({ msg: 'Classroom not found' });
        
        // ตรวจสอบว่า requester เป็น creator
        // ✨ แก้ไข: ตรวจสอบ creator
        if (!classroom.creator.map(id => id.toString()).includes(req.user.id.toString())) {
            return res.status(403).json({ msg: 'Only creator can kick members' });
        }

        // ✨ เพิ่ม: ป้องกันการเตะ creator คนอื่น
        if (classroom.creator.map(id => id.toString()).includes(userId)) {
            return res.status(403).json({ msg: 'Cannot kick another creator. Only the original creator can demote creators.' });
        }

        // ลบออกจาก participants
        classroom.participants = classroom.participants.filter(
            id => id.toString() !== userId
        );
        // ลบออกจาก assignedUsers
        for (const key in classroom.assignedUsers) {
            if (classroom.assignedUsers[key]?.userId === userId) {
                delete classroom.assignedUsers[key];
            }
        }
        
        // Mongoose maps don't track deletes, so we need to mark it as modified.
        classroom.markModified('assignedUsers');
        await classroom.save();
        res.json({ msg: 'Kicked successfully', classroom });
    } catch (err) {
        console.error("Error in kick route:", err);
        res.status(500).json({ msg: 'Server error' });
    }
});

// ** เพิ่มโค้ดนี้: Route สำหรับโปรโมทผู้ใช้เป็น creator ของห้องเรียน **
app.put('/api/classrooms/:classId/promote', authMiddleware, async (req, res) => {
    const { classId } = req.params;
    const { userId } = req.body;
    try {
        const classroom = await Class.findById(classId);
        if (!classroom) return res.status(404).json({ msg: 'Classroom not found' });

        // ✨ แก้ไข: ตรวจสอบว่า requester เป็น creator หรือไม่
        if (!classroom.creator.map(id => id.toString()).includes(req.user.id.toString())) {
            return res.status(403).json({ msg: 'Only a creator can promote members' });
        }

        // ✨ แก้ไข: เปิดใช้งาน Logic การโปรโมท
        // ตรวจสอบว่า user ยังไม่ได้เป็น creator
        if (classroom.creator.map(id => id.toString()).includes(userId.toString())) {
            return res.status(400).json({ msg: 'User is already a creator' });
        }

        // เพิ่ม userId เข้าไปใน array ของ creator
        classroom.creator.push(userId);
        await classroom.save();
        // เพิ่ม classId เข้าไปใน createdClasses ของ user ที่ถูกโปรโมท
        await User.findByIdAndUpdate(userId, { $addToSet: { createdClasses: classId } });
        res.json({ msg: 'Promoted successfully', classroom });
    } catch (err) {
        console.error("Error promoting user:", err);
        res.status(500).json({ msg: 'Server error' });
    }
});

// ** เพิ่มโค้ดนี้: Route สำหรับลดระดับ creator กลับเป็น participant **
app.put('/api/classrooms/:classId/demote', authMiddleware, async (req, res) => {
    const { classId } = req.params;
    const { userId } = req.body; // User ID to be demoted

    try {
        const classroom = await Class.findById(classId);
        if (!classroom) return res.status(404).json({ msg: 'Classroom not found' });

        // ✨ แก้ไข: ตรวจสอบว่า requester เป็น "ผู้สร้างห้องคนแรก" หรือไม่
        // ผู้สร้างคนแรกคือคนแรกใน array ของ creator
        const originalCreatorId = classroom.creator[0]?.toString();
        if (req.user.id.toString() !== originalCreatorId) {
            return res.status(403).json({ msg: 'Only a creator can demote members' });
        }

        // ✨ แก้ไข: เปิดใช้งาน Logic การลดระดับ
        // ป้องกันการลดระดับ creator คนสุดท้าย
        if (classroom.creator.length <= 1) {
            return res.status(400).json({ msg: 'Cannot demote the last creator of the classroom.' });
        }

        // ลบ user ออกจาก array ของ creator
        classroom.creator = classroom.creator.filter(id => id.toString() !== userId.toString());
        await classroom.save();

        // ลบ classId ออกจาก createdClasses ของ user ที่ถูกลดระดับ
        await User.findByIdAndUpdate(userId, { $pull: { createdClasses: classId } });

        res.json({ msg: 'User demoted successfully', classroom });
    } catch (err) {
        console.error("Error demoting user:", err);
        res.status(500).json({ msg: 'Server error' });
    }
});

// Route to update classroom theme
app.put('/api/classrooms/:classId/theme', authMiddleware, async (req, res) => {
    const { classId } = req.params;
    const { name, subname, color, bannerUrl } = req.body;
    const userId = req.user.id;

    try {
        const classroom = await Class.findById(classId);

        if (!classroom) {
            return res.status(404).json({ msg: 'Classroom not found' });
        }

        // Check if the user is a creator of the classroom
        if (!classroom.creator.map(id => id.toString()).includes(userId.toString())) {
            return res.status(403).json({ msg: 'Authorization denied. Only creators can edit the theme.' });
        }

        // Update the classroom fields
        classroom.name = name || classroom.name;
        classroom.subname = subname || classroom.subname;
        classroom.color = color || classroom.color;
        classroom.bannerUrl = bannerUrl; // Can be an empty string to remove it

        const updatedClassroom = await classroom.save();
        res.json(updatedClassroom);
    } catch (err) {
        console.error("Error updating classroom theme:", err);
        res.status(500).send('Server error');
    }
});

// Route to update classroom settings (isPublic, allowSelfJoin)
app.put('/api/classrooms/:classId/settings', authMiddleware, async (req, res) => {
    const { classId } = req.params;
    const { isPublic, allowSelfJoin } = req.body;
    const userId = req.user.id;

    try {
        const classroom = await Class.findById(classId);

        if (!classroom) {
            return res.status(404).json({ msg: 'Classroom not found' });
        }

        // Check if the user is a creator of the classroom
        if (!classroom.creator.map(id => id.toString()).includes(userId.toString())) {
            return res.status(403).json({ msg: 'Authorization denied. Only creators can edit classroom settings.' });
        }

        // Update the classroom settings
        if (typeof isPublic === 'boolean') {
            classroom.isPublic = isPublic;
        }
        if (typeof allowSelfJoin === 'boolean') {
            classroom.allowSelfJoin = allowSelfJoin;
        }

        const updatedClassroom = await classroom.save();
        res.json(updatedClassroom);
    } catch (err) {
        console.error("Error updating classroom settings:", err);
        res.status(500).send('Server error');
    }
});

// Banner upload configuration
const bannerStorage = multer.diskStorage({
    destination: function (req, file, cb) {
        const uploadPath = path.join(__dirname, 'uploads', 'banners');
        if (!fs.existsSync(uploadPath)) {
            fs.mkdirSync(uploadPath, { recursive: true });
        }
        cb(null, uploadPath);
    },
    filename: function (req, file, cb) {
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        cb(null, 'banner-' + uniqueSuffix + path.extname(file.originalname));
    }
});

const bannerUpload = multer({
    storage: bannerStorage,
    limits: {
        fileSize: 5 * 1024 * 1024 // 5MB limit
    },
    fileFilter: function (req, file, cb) {
        if (file.mimetype.startsWith('image/')) {
            cb(null, true);
        } else {
            cb(new Error('Only image files are allowed!'), false);
        }
    }
});

// 10.5. Banner Upload Endpoint
app.post('/api/classrooms/:id/banner', authMiddleware, bannerUpload.single('banner'), async (req, res) => {
    try {
        const classroom = await Class.findById(req.params.id);
        if (!classroom) {
            return res.status(404).json({ message: 'Classroom not found' });
        }

        // Check if user is creator
        const isCreator = classroom.creator.some(creatorId => creatorId.toString() === req.user.id);
        if (!isCreator) {
            return res.status(403).json({ message: 'Access denied. Only creators can upload banners.' });
        }

        if (!req.file) {
            return res.status(400).json({ message: 'No file uploaded' });
        }

        // Delete old banner file if exists
        if (classroom.bannerUrl) {
            const oldBannerPath = path.join(__dirname, classroom.bannerUrl.replace('/uploads', 'uploads'));
            if (fs.existsSync(oldBannerPath)) {
                fs.unlinkSync(oldBannerPath);
            }
        }

        // Save new banner URL
        const bannerUrl = `/uploads/banners/${req.file.filename}`;
        classroom.bannerUrl = bannerUrl;
        await classroom.save();

        res.json({ bannerUrl });
    } catch (err) {
        console.error("Error uploading banner:", err);
        res.status(500).json({ message: 'Server error' });
    }
});

// Debug endpoint to check email existence
app.get('/api/debug/check-email/:email', async (req, res) => {
    try {
        const email = req.params.email;
        const users = await User.find({
            email: { $regex: new RegExp(email, 'i') }
        }, { email: 1, displayName: 1, _id: 1 });
        
        const exactMatch = await User.findOne({ email: email.toLowerCase().trim() });
        
        res.json({
            searchEmail: email,
            normalizedEmail: email.toLowerCase().trim(),
            similarEmails: users,
            exactMatch: exactMatch ? { 
                id: exactMatch._id, 
                email: exactMatch.email, 
                displayName: exactMatch.displayName 
            } : null
        });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Test registration endpoint
app.post('/api/debug/test-register', async (req, res) => {
    const { email, password, displayName } = req.body;
    
    try {
        console.log('=== DEBUG REGISTRATION TEST ===');
        console.log('Original email:', email);
        console.log('Normalized email:', email.toLowerCase().trim());
        
        // Check for existing user
        const existingUser = await User.findOne({ email: email.toLowerCase().trim() });
        console.log('Existing user found:', existingUser ? existingUser.email : 'None');
        
        if (existingUser) {
            return res.json({
                success: false,
                message: 'User already exists',
                existingUser: {
                    id: existingUser._id,
                    email: existingUser.email,
                    displayName: existingUser.displayName
                }
            });
        }
        
        res.json({
            success: true,
            message: 'Email is available for registration',
            normalizedEmail: email.toLowerCase().trim()
        });
        
    } catch (err) {
        console.error('Debug registration error:', err);
        res.status(500).json({ error: err.message });
    }
});

// 11. Start Server
server.listen(port, () => {
    console.log(`Server is running on port: ${port}`);
    console.log(`Socket.IO server is ready`);
});