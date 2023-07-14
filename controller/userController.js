const crypto = require("crypto");
const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const parser = require("ua-parser-js");
const Cryptr = require('cryptr');

const User = require("../models/userModel");
const { generateToken, hashToken } = require("../utils");
const sendEmail = require("../utils/sendEmail");
const Token = require("../models/tokenModel");
const db = require('../Database/db');


const cryptr = new Cryptr(process.env.CRYPTER_KEY);








// Register USER
const register = asyncHandler(async (req, res) => {
    const { name, email, password } = req.body;

    // validation
    if (!name || !email || !password) {
        res.status(400)
        throw new Error("Please fill in all the require fields.");
    }
    if (password.length < 6) {
        res.status(400)
        throw new Error("Password must not less than 6 characters.");
    }


    // check if the user exists
    db.query(`SELECT email FROM glopilot.users = ?`[email], async (err, userExists) => {
        console.log(err);
        if (userExists) return res.json({ status: "error", error: "User exist already login instead" });

        // Get UserAgent
        const ua = parser(req.headers['user-agent']);
        const userAgent = [ua.ua]

        // Create new user 
        userExists = db.query('INSERT INTO users SET ?', {
            name: name,
            email: email,
            password: password,
            userAgent: userAgent
        }, (err, user) => {
            if (err) throw err;
            console.log(user);
        })

        // Generate Token 
        const token = generateToken(user.id);

        // Send HTTP 
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: "none",
            // secure: true,
        }); if (user) {
            const { _id, name, email, number, bio, photo, role, isVerified } = user;

            res.status(201).json({
                _id,
                name,
                email,
                number,
                bio,
                photo,
                role,
                isVerified,
                token
            })
        } else {
            res.status(400)
            throw new Error("Invalid user input");
        }

    })







});
// Login USERS
const loginUser = asyncHandler(async (req, res) => {
    const { email, password } = req.body;

    // verification

    if (!email || !password) {
        res.status(400)
        throw new Error("please enter email and password");
    }

    // const user = await User.findOne({ email });
    const user = await ` INSERT INTO users (name,email,password) VALUES(?) `


    if (!user) {
        res.status(404)
        throw new Error("user does't exist");
    }

    const passwordIsCorrect = await bcrypt.compare(password, user.password);

    if (!passwordIsCorrect) {
        res.status(400)
        throw new Error("Invalid email or password");
    }

    //  Trigger 2FA for unknow userAgent

    // Get UserAgent
    const ua = parser(req.headers['user-agent']);
    const thisUserAgent = ua.ua;

    console.log(thisUserAgent);

    const allowedAgent = user.userAgent.includes(thisUserAgent);

    if (!allowedAgent) {
        // Generate 6 digit code
        const loginCode = Math.floor(100000 + Math.random() * 900000);

        console.log(loginCode);
        // Encrypt loginCode before saving to Database
        const encryptedLoginCode = cryptr.encrypt(loginCode.toString());

        // Delete token if its exist in Database
        let userToken = await Token.findOne({ userId: user._id })
        if (userToken) {
            await userToken.deleteOne()
        }


        // Save token and save 

        await new Token({
            userId: user._id,
            loginToken: encryptedLoginCode,
            createAt: Date.now(),
            expireAt: Date.now() + 60 * (60 * 1000) // 1hr
        }).save();

        res.status(400)
        throw new Error("New device detected, Check your email for login code");

    }


    // Generate Token 
    const token = generateToken(user._id);


    if (user && passwordIsCorrect) {
        // Send HTTP 
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: "none",
            // secure: true,
        });
        const { _id, name, email, number, bio, photo, role, isVerified } = user;

        res.status(201).json({
            _id,
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
});

//  Send Login Code
const sendLoginCode = asyncHandler(async (req, res) => {
    const { email } = req.params;
    const user = await User.findOne({ email });

    if (!user) {
        res.status(404)
        throw new Error("user not found");
    }
    // Find Login Code in DB
    let userToken = await Token.findOne({ userId: user._id, expireAt: { $gt: Date.now() } });
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
    let userToken = await Token.findOne({ userId: user._id, expireAt: { $gt: Date.now() } });
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
        const token = generateToken(user._id);

        // Send HTTP 
        res.cookie("token", token, {
            path: "/",
            httpOnly: true,
            expires: new Date(Date.now() + 1000 * 86400), // 1 day
            sameSite: "none",
            // secure: true,
        })
        const { _id, name, email, number, bio, photo, role, isVerified } = user;

        res.status(201).json({
            _id,
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
// LOGOUT USERS
const logOut = asyncHandler(async (req, res) => {

    res.cookie("token", "", {
        path: "/",
        httpOnly: true,
        expires: new Date(Date.now() + 1000 * 86400), // 1 day
        sameSite: "none",
        secure: true,
    });
    return res.status(200).json({
        message: "Logout successful"
    })
});

// Get all USERS
const getUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);

    if (user) {
        const { _id, name, email, number, bio, photo, role, isVerified } = user;

        res.status(201).json({
            _id,
            name,
            email,
            number,
            bio,
            photo,
            role,
            isVerified,

        })
    } else {
        res.status(400)
        throw new Error("user not found");
    }
});

// Update USERS
const updateUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);
    if (user) {
        const { _id, name, email, number, bio, photo, role, isVerified } = user;

        user.name = req.body.name || name
        user.email = email
        user.number = req.body.number || number
        user.bio = req.body.bio || bio
        user.photo = req.body.photo || photo

        const updatedUser = await user.save();

        res.status(201).json({
            _id: updatedUser._id,
            name: updatedUser.name,
            email: updatedUser.email,
            number: updatedUser.number,
            bio: updatedUser.bio,
            photo: updatedUser.photo,
            role: updatedUser.role,
            isVerified: updatedUser.isVerified,

        })
    } else {
        res.status(400)
        throw new Error("user not found");
    }

});

// Delete USERS
const deleteUser = asyncHandler(async (req, res) => {
    const user = await User.findById(req.params.id);
    if (!user) {
        res.status(400)
        throw new Error("user not found");
    }
    try {
        await user.deleteOne();
    } catch (err) {
        res.status(400)
        throw new Error("user delete not successfully");
    }
    res.status(200).json({
        message: "user delete successfully"
    });

});

// Get All USERS
const getAllUsers = asyncHandler(async (req, res) => {
    const user = await 'SELECT * FROM glopilot.users';
    db.query(user, (err, data) => {
        if (err) {
            res.status(500).json({
                message: "Something went wrong "
            });
        }
        res.status(200).json(data);
    })


})

// Get All USERS Status
const loginStatus = asyncHandler(async (req, res) => {
    const token = req.cookies.token;
    if (!token) {
        return res.json(false)
    }
    // verified token
    const verified = jwt.verify(token, process.env.JWT_SECTRET);
    if (verified) {
        return res.json(true)
    } else {
        return res.json(false)
    }
});

// Upgrade USERS Change users role
const upgradeUser = asyncHandler(async (req, res) => {
    const { role, id } = req.body;

    const user = await User.findById(id);
    if (!user) {
        res.status(404).json({
            message: "User not found"
        });
    }
    user.role = role;
    await user.save();

    res.status(200).json({
        message: `User role updated to ${role}`
    });
});

// Send Automated Email to All USERS
const sendAutomatedEmail = asyncHandler(async (req, res) => {
    const { subject, send_to, reply_to, template, url } = req.body;

    if (!subject || !send_to || !reply_to || !template) {
        res.status(500)
        throw new Error("Missing Email parameter");
    }

    // Get user
    const user = User.findOne({ email: send_to });
    if (!user) {
        res.status(404)
        throw new Error("no user with this");
    }
    const sent_from = process.env.EMAIL_USER;
    const name = user.name;
    const link = process.env.FRONTEND_URL;

    try {
        await sendEmail(subject, send_to, sent_from, reply_to, template, name, link);
        res.status(200).json({ message: "Email sent" });
    } catch (error) {
        res.status(500)
        throw new Error("Email not send please try again");
    }

});

//  Forgot Password 
const forgotPassword = asyncHandler(async (req, res) => {
    const { email } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
        res.status(404)
        throw new Error("user not found");
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
        resetToken: hashedToken,
        createAt: Date.now(),
        expireAt: Date.now() + 60 * (60 * 1000) // 1hr
    }).save();


    // Construction Reset URL
    const resetUrl = `${process.env.FRONTEND_URL}/resetPassword/${resetToken}`;

    // Send Email tomy user
    const subject = 'Password reset Request from Glopilot'
    const send_to = user.email
    const sent_from = process.env.EMAIL_USER
    const reply_to = "noreply"
    const template = 'forgotPassword'
    const name = user.name
    const link = resetUrl

    try {
        await sendEmail(
            subject,
            send_to,
            sent_from,
            reply_to,
            template,
            name,
            link);
        res.status(200).json({ message: "Password Reset Email sent" });
    } catch (error) {
        res.status(500)
        throw new Error("Email not send please try again");
    }

});

// Reset Password
const resetPassword = asyncHandler(async (req, res) => {
    const { resetToken } = req.params;
    const { password } = req.body;

    const hashedToken = hashToken(resetToken);

    const userToken = await Token.findOne({
        resetToken: hashedToken,
        expireAt: { $gt: Date.now() }
    })

    if (!userToken) {
        res.status(404)
        throw new Error("invalid Token or Expired Token");
    }

    // Find User
    const user = await User.findOne({ _id: userToken.userId });


    //  Now Reset user Password
    user.password = password;
    await user.save();
    res.status(200).json({
        message: "Your Password successful Change, please login"

    });

});

// Change Password
const changePassword = asyncHandler(async (req, res) => {
    const { oldPassword, password } = req.body;
    const user = await User.findById(req.user._id);

    if (!user) {
        res.status(404)
        throw new Error("user not found");
    }
    if (!oldPassword) {
        res.status(400)
        throw new Error("please enter old and new password");
    }

    // Check if old password is current
    const passwordIsCorrect = await bcrypt.compare(oldPassword, user.password);

    // Save new password
    if (user && passwordIsCorrect) {
        user.password = password
        await user.save();
        res.status(200).json({
            message: 'Password change successful, please re-login'
        })

    } else {
        res.status(400)
        throw new Error("Old password is incorrect");
    }
})
module.exports = {
    register,
    loginUser,
    logOut,
    getUser,
    updateUser,
    deleteUser,
    getAllUsers,
    loginStatus,
    upgradeUser,
    sendAutomatedEmail,
    sendVerificationEmail,
    verifyUser,
    forgotPassword,
    resetPassword,
    changePassword,
    sendLoginCode,
    loginWithCode
}