import User from "../models/user.models.js";
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { sendMail, emailVerificationMailGenContent, forgotPasswordMailGenContent } from '../utils/mail.js';
import {ApiError} from '../utils/api-error.js'
import {ApiResponse} from '../utils/api-response.js'
import {asyncHandler} from '../utils/async-handler.js'

// Register User
const registerUser = asyncHandler(async (req, res) => {

    // Request data from user body
    const { name, username, email, mobileno, password } = req.body;

    // Checks for all required field
    if (!name || !username || !email || !password || !mobileno) {
        throw new ApiError(400, "All fields are required");
    }

    // User already exists
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
        throw new ApiError(409, "User with this email or username already exists");
    }

    // Created an temporaary token
    const token = crypto.randomBytes(32).toString("hex");

    // Created an user
    const user = await User.create({
        name,
        username,
        email,
        mobileno,
        password,
        emailVerificationToken: token,
        emailVerificationExpiry: Date.now() + 60 * 60 * 1000,
    });

    // Send this url in mail
    const verificationUrl = `${process.env.BASE_URL}/api/v1/verify/${token}`;

    // Send mail to verify
    await sendMail({
        email,
        subject: "Verify Email",
        mailGenContent: emailVerificationMailGenContent(user.username, verificationUrl)
    });

    res.status(201).json(new ApiResponse(201, user, "User registered successfully"));
});

// Verify Email
const verifyEmail = asyncHandler(async (req, res) => {
    const { token } = req.params;

    const user = await User.findOne({ emailVerificationToken: token });

    if (!user || user.emailVerificationExpiry < Date.now()) {
        throw new ApiError(400, "Invalid or expired verification token");
    }

    user.isEmailVerified = true;
    user.emailVerificationToken = undefined;
    user.emailVerificationExpiry = undefined;

    await user.save();

    res.status(200).json(new ApiResponse(200, {}, "Email verified successfully"));
});

// Login User
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        throw new ApiError(400, "Email and password are required");
    }

    const user = await User.findOne({ email });

    if (!user || !(await user.isPasswordCorrect(password))) {
        throw new ApiError(401, "Invalid email or password");
    }

    if (!user.isEmailVerified) {
        throw new ApiError(403, "Please verify your email");
    }

    const token = await user.generateAccessToken();

    console.log("=== Login Controller Debug ===");
    console.log("Token generated:", token);

    // Set cookie with minimal options for testing
    const cookieOptions = {
      httpOnly: false, // Set to false for testing
      secure: false, // Set to false for local development
      sameSite: "lax",
      path: "/",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    };

    console.log("Cookie options:", cookieOptions);

    // Set cookie before sending response
    res.cookie("token", token, cookieOptions);

    // Log headers to verify cookie is set
    // console.log("Response headers:", res.getHeaders());

    // res.status(200).json({
    //   success: true,
    //   message: "Login successful",
    //   token,
    //   user: {
    //     id: user._id,
    //     name: user.name,
    //     role: user.role,
    //   },
    // });

    res.status(200).json(new ApiResponse(200, { user, token }, "Login successful"));
});

// Logout
const logoutUser = asyncHandler(async (req, res) => {
    res.clearCookie("token");
    res.status(200).json(new ApiResponse(200, {}, "Logout successful"));
});

// Resend Email Verification
const resendVerificationEmail = asyncHandler(async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) throw new ApiError(404, "User not found");

    const token = crypto.randomBytes(32).toString("hex");
    user.emailVerificationToken = token;
    user.emailVerificationExpiry = Date.now() + 3600000;
    await user.save();

    const verificationUrl = `${process.env.BASE_URL}/api/v1/verify/${token}`;

    await sendMail({
        email,
        subject: "Resend Email Verification",
        mailGenContent: emailVerificationMailGenContent(user.username, verificationUrl)
    });

    res.status(200).json(new ApiResponse(200, {}, "Verification email resent"));
});

// Refresh Token
const refreshAccessToken = asyncHandler(async (req, res) => {
    const { token } = req.params;
    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const newToken = jwt.sign({ id: decoded.id }, process.env.JWT_SECRET, { expiresIn: "7d" });

        res.status(200).json(new ApiResponse(200, { token: newToken }, "Token refreshed"));
    } catch (err) {
        throw new ApiError(401, "Invalid refresh token");
    }
});

// Forgot Password Request
const forgotPasswordRequest = asyncHandler(async (req, res) => {

    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) throw new ApiError(404, "User not found");

    const token = crypto.randomBytes(32).toString("hex");
    
    user.forgotPasswordToken = token;
    user.forgotPasswordExpiry = Date.now() + 3600000;
    await user.save();

    const resetUrl = `${process.env.BASE_URL}/api/v1/reset-password/${token}`;

    await sendMail({
        email,
        subject: "Reset Password",
        mailGenContent: forgotPasswordMailGenContent(user.username, resetUrl)
    });

    res.status(200).json(new ApiResponse(200, {}, "Password reset email sent"));
});

// Change Password
const changeCurrentPassword = asyncHandler(async (req, res) => {
    const { token, newPassword } = req.body;

    const user = await User.findOne({ forgotPasswordToken: token });

    if (!user || user.forgotPasswordExpiry < Date.now()) {
        throw new ApiError(400, "Invalid or expired reset token");
    }

    user.password = newPassword;
    user.forgotPasswordToken = undefined;
    user.forgotPasswordExpiry = undefined;
    await user.save();

    res.status(200).json(new ApiResponse(200, {}, "Password changed successfully"));
});

// Get Current User
const getCurrentUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user.id);
    res.status(200).json(new ApiResponse(200, user, "User fetched successfully"));
});

export {
    registerUser,
    getCurrentUser,
    changeCurrentPassword,
    forgotPasswordRequest,
    refreshAccessToken,
    resendVerificationEmail,
    verifyEmail,
    loginUser,
    logoutUser
};
