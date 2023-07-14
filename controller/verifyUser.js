const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const parser = require("ua-parser-js");
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPTER_KEY);
const sendEmail = require("../utils/sendEmail");

const { generateToken, hashToken } = require("../utils");

const db = require('../Database/db');

// verify Users
const verifyUser = asyncHandler(async (req, res) => {
    const { verificationToken } = req.params;
    const hashedToken = hashToken(verificationToken);

    const userToken = await Token.findOne({
        verifyToken: hashedToken,
        expireAt: { $gt: Date.now() }
    })

    if (!userToken) {
        res.status(404)
        throw new Error("invalid Token or Expired Token");
    }

    // Find User
    const user = await User.findOne({ _id: userToken.userId });

    if (user.isVerified) {
        res.status(400)
        throw new Error("user is already verfied");
    }
    //  Now verify user
    user.isVerified = true;
    await user.save();
    res.status(200).json({
        message: "Account verification successful"

    })
})

module.exports = verifyUser;