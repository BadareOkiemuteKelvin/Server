const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const parser = require("ua-parser-js");
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPTER_KEY);
const sendEmail = require("../utils/sendEmail");

const { generateToken, hashToken } = require("../utils");

const db = require('../Database/db');


//  Send verification Email
const sendVerificationEmail = asyncHandler(async (req, res) => {
    const user = User.findById(req.user._id);
    if (!user) {
        res.status(404)
        throw new Error("user not found");
    }
    if (user.isVerified) {
        res.status(400)
        throw new Error("user already verified");
    }
    // Delete token if its exist in Database
    let token = await Token.findOne({ userId: user._id })
    if (token) {
        await token.deleteOne()
    }
    // Create verification Token and Save
    const resetToken = crypto.randomBytes(32).toString("hex") + user._id;

    // Hash token and save 
    const hashedToken = hashToken(resetToken);

    await new Token({
        userId: user._id,
        verifyToken: hashedToken,
        createAt: Date.now(),
        expireAt: Date.now() + 60 * (60 * 1000) // 1hr
    }).save();


    // Construction verification URL
    const verificationUrl = `${process.env.FRONTEND_URL}/verify/${resetToken}`;

    // Send Email tomy user
    const subject = 'Verify your Account Glopilot'
    const send_to = user.email
    const sent_from = process.env.EMAIL_USER
    const reply_to = "noreply"
    const template = 'verifyEmail'
    const name = user.name
    const link = verificationUrl

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link);
        res.status(200).json({ message: "Verification Email sent" });
    } catch (error) {
        res.status(500)
        throw new Error("Email not send please try again");
    }
});

module.exports = sendVerificationEmail;