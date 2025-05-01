import mongoose, { Schema } from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken"
import crypto from 'crypto'

const userSchema = new Schema({
    name: {
        type: String,
        required: true,
    },
    email: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    username: {
        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },
    password: {
        type: String,
        required: true,
    },
    mobileno: {
        type: String,
        required: true,
    },
    isEmailVerified: {
        type: Boolean,
        default: false,
    },
    forgotPasswordToken: {
        type: String,
        default: false 
    },
    forgotPasswordExpiry: {
        type: Date,
    },
    refreshToken: {
        type: String
    },
    emailVerificationToken: {
        type: String
    },
    emailVerificationExpiry: {
        type: Date
    },
}, {timestamps: true})

userSchema.pre("save", async function (next) {
    if(!this.isModified("password")) return next();
    this.password = await bcrypt.hash(this.password, 10)
    next()
})

userSchema.methods.isPasswordCorrect = async function (password) {
    return await bcrypt.compare(password, this.password)
}

userSchema.methods.generateAccessToken = async function(){
    return jwt.sign(
        {
            _id: this._id,
            email: this.email,
            name: this.name
        },
        process.env.ACCESS_TOKEN_SECRET,
        {expiresIn: process.env.ACCESS_TOKEN_EXPIRY}
    )
}

userSchema.methods.generateRefreshjToken = async function(){
    return jwt.sign(
        {
            _id: this._id,
        },
        process.env.REFRESH_TOKEN_SECRET,
        {expiresIn: process.env.REFRESH_TOKEN_EXPIRY}
    )
}

userSchema.methods.genrateTemporaryToken = function(){
    const unHashedToken = crypto.randomBytes(20).toString('hex');

    const hashedToken = crypto.createHash("sha256").update(unHashedToken).digest("hex");
    const tokenExpiry = Date.now() + (20*60*1000);

    return {unHashedToken, hashedToken, tokenExpiry};
}

const User = mongoose.model("User", userSchema);

export default User;