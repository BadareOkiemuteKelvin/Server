const asyncHandler = require("express-async-handler");
const db = require('../../Database/db');

// Get all USERS
const getUser = asyncHandler(async (req, res) => {
    const userId = req.params.id;
    // const user = await User.findById(req.user._id);
    const q = 'SELECT * FROM glopilot.users WHERE id = ?';
    db.query(q, [userId], (err, user) => {
        console.log(user);
        if (err) {
            return res.status(500).json({
                message: "Something went wrong"
            })
        }
        if (user) {
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

            })
        } else {
            res.status(400)
            throw new Error("user not found");
        }

    })


});


module.exports = getUser;