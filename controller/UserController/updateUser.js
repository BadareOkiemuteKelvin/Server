const asyncHandler = require("express-async-handler");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const parser = require("ua-parser-js");
const Cryptr = require('cryptr');
const cryptr = new Cryptr(process.env.CRYPTER_KEY);
const sendEmail = require("../../utils/sendEmail");

const { generateToken, hashToken } = require("../../utils");

const db = require('../../Database/db');


// Update USERS
const updateUser = asyncHandler(async (req, res) => {
    // const user = await User.findById(req.user._id);
    const q = 'SELECT * FROM glopilot.users WHERE id = ?';
    db.query(q, [userId], async (err, user) => {
        console.log(user);
        if (err) {
            return res.status(500).json({
                message: "Something went wrong"
            })
        }

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
    })
});
module.exports = updateUser;