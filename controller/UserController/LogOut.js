const asyncHandler = require("express-async-handler");

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

module.exports = logOut;