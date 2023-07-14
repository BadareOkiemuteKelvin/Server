const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const parser = require("ua-parser-js");
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPTER_KEY);
const sendEmail = require("../utils/sendEmail");

const { generateToken, hashToken } = require("../utils");

const db = require('../Database/db');


// login With Code
const loginWithCode = asyncHandler(async (req, res) => {
    const { email } = req.params;
    const { loginCode } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
        res.status(404)
        throw new Error("user not found");
    }

    // Find Login Code in DB
    let userToken = await Token.findOne({ userId: user.id, expireAt: { $gt: Date.now() } });
    if (!userToken) {
        res.status(404)
        throw new Error("Invalid or Expire Token, please Login again");
    }

    const decryptedLoginCode = cryptr.decrypt(userToken.loginToken);

    if (loginCode !== decryptedLoginCode) {
        res.status(400)
        throw new Error("Invalid login Code, please Login again");
    } else {
        // Register UA
        const ua = parser(req.headers['user-agent']);
        const thisUserAgent = ua.ua;

        console.log(thisUserAgent);

        user.userAgent.push(thisUserAgent);
        await user.save();

        // Generate Token 
        const token = generateToken(user.id);
        // Send HTTP 
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: "none",
            // secure: true,
        })
        const { id, name, email, number, bio, photo, role, isVerified } = user;

        res.status(201).json({
            id,
            name,
            email,
            number,
            bio,
            photo,
            role,
            isVerified,
            token
        });
    }

})

module.exports = loginWithCode;