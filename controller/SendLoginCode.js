const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const parser = require("ua-parser-js");
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPTER_KEY);
const sendEmail = require("../utils/sendEmail");

const { generateToken, hashToken } = require("../utils");

const db = require('../Database/db');
//  Send Login Code
const sendLoginCode = asyncHandler(async (req, res) => {
    const { email } = req.params;
    // const user = await User.findOne({ email });
    const q = ' SELECT * FROM glopilot.users WHERE email = ?'

    db.query(q, [email], async (err, user) => {
        if (!user) {
            res.status(404)
            throw new Error("user not found");
        }
        console.log(user);
        // Find Login Code in DB
        let uToken = await 'SELECT * FROM glopilot.token WHERE userId = ?, (`userId`, `expireAt`)  VALUES (?)';
        const VALUES =
        {
            userId: user.id,
            expireAt: { $gt: Date.now() }
        }

        db.query(uToken, [VALUES], async (err, userToken) => {
            console.log(userToken);
            if (err) return console.log(err);
            if (!userToken) {
                res.status(404)
                throw new Error("Invalid or Expire Token, please Login again");
            }
            const loginCode = userToken.loginToken;
            const decryptedLoginCode = cryptr.decrypt(loginCode);

            // Send Login Code Email to user
            const subject = 'Login Access from Glopilot'
            const send_to = email
            const sent_from = process.env.EMAIL_USER
            const reply_to = "noreply"
            const template = 'Login Code'
            const name = user.name
            const link = decryptedLoginCode


            try {
                await sendEmail(
                    subject,
                    send_to,
                    sent_from,
                    reply_to,
                    template,
                    name,
                    link);
                res.status(200).json({ message: `Access Code to sent ${email} Email` });
            } catch (error) {
                res.status(500)
                throw new Error("Email not send please try again");
            }
        });





    })



});

module.exports = sendLoginCode;