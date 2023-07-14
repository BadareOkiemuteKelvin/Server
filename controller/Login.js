const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const parser = require("ua-parser-js");
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPTER_KEY);

const { generateToken, hashToken } = require("../utils");

const db = require('../Database/db');

// Login USERS
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;
    // verification
    if (!email || !password) {
        res.status(400)
        throw new Error("please enter email and password");
    }

    // const user = await User.findOne({ email });
    const q = ' SELECT * FROM glopilot.users WHERE email = ?'

    db.query(q, [email], async (err, user) => {
        if (err) return console.log(err);
        if (!user[0]) {
            // || !await bcrypt.compare(password, user[0].password)
            return res.status(201).json({ message: "Invalid email or password" });
        }

        //  Trigger 2FA for unknow userAgent
        // Get UserAgent
        const ua = parser(req.headers['user-agent']);
        const thisUserAgent = ua.ua;

        console.log(thisUserAgent);

        const allowedAgent = user.userAgent;


        if (!allowedAgent) {
            // Generate 6 digit code
            const loginCode = Math.floor(100000 + Math.random() * 900000);

            console.log(loginCode);
            // Encrypt loginCode before saving to Database
            const encryptedLoginCode = await cryptr.encrypt(loginCode.toString());
            console.log(encryptedLoginCode);
            // Delete token if its exist in Database
            let userToken = await jwt.sign({ id: user[0].id }, process.env.JWT_SECTRET);

            if (userToken) {
                const Token = 'DELETE * FROM glopilot.token WHERE token = ?'
                db.query(Token, [user], async (err, data) => {
                    if (err) throw err;
                    await userToken.Token
                    console.log(data.Token)
                    throw new Error("token delete successfully");
                })
                // Save token and save 
                const cookieOption = ({
                    // expiresIn:
                    userId: user[0].id,
                    loginToken: encryptedLoginCode,
                    createAt: Date.now(),
                    expireAt: Date.now() + 60 * (60 * 1000) // 1hr
                });
                console.log(cookieOption);
                throw new Error("New device detected, Check your email for login code");
            }

        }
        // Generate Token 
        const token = generateToken(user.id);
        console.log(token);

        if (user) {
            // Send HTTP 
            res.cookie("token", token, {
                path: "/",
                httpOnly: true,
                expires: new Date(Date.now() + 1000 * 86400), // 1 day
                sameSite: "none",
                // secure: true,

            });
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

        } else {
            res.status(500)
            throw new Error("Something went wrong");
        }

    })
});

module.exports = loginUser;