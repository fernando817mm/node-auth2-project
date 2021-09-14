const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const { JWT_SECRET, BCRYPT_NUM } = require("../secrets"); // use this secret!
const User = require("../users/users-model");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

router.post("/register", validateRoleName, async (req, res, next) => {
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
  try {
    const { password } = req.body;
    const hash = bcrypt.hashSync(password, BCRYPT_NUM);
    const newUser = await User.add({ ...req.body, password: hash });
    res.status(201).json(newUser);
  } catch (err) {
    next(err);
  }
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */ const { user } = req;
  if (bcrypt.compareSync(req.body.password, user.password)) {
    const payload = {
      subject: user.user_id,
      username: user.username,
      role_name: user.role_name,
    };
    const options = {
      expiresIn: "1d",
    };
    const token = jwt.sign(payload, JWT_SECRET, options);
    res.status(200).json({ message: `${user.username} is back!`, token });
  } else {
    next({ status: 401, message: "Invalid credentials" });
  }
});

module.exports = router;
