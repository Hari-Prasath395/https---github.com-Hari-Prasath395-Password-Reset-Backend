const express = require("express");
const router = new express.Router();
const userdb = require("../Model/userSchema");
var bcrypt = require("bcrypt");
const authenticate = require("../Middleware/Authentication");
const nodemailer = require("nodemailer");
const jwt = require("jsonwebtoken");


const keysecret = process.env.SECRET_KEY;

let transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.AUTH_EMAIL,
    pass: process.env.AUTH_PASS,
  },
});

transporter.verify((error, success) => {
  if (error) {
    console.log(error);
  } else {
    console.log("Ready to message");
    console.log(success);
  }
});

// for user registration

router.post("/register", async (req, res) => {
  const { fname, email, password, cpassword } = req.body;

  if (!fname || !email || !password || !cpassword) {
    res.status(422).json({ error: "fill all the details" });
  }

  try {
    const preuser = await userdb.findOne({ email: email });

    if (preuser) {
      res.status(422).json({ error: "This Email is Already Exist" });
    } else if (password !== cpassword) {
      res
        .status(422)
        .json({ error: "Password and Confirm Password Not Match" });
    } else {
      const finalUser = new userdb({
        fname,
        email,
        password,
        cpassword,
      });

      const storeData = await finalUser.save();

      // console.log(storeData);
      res.status(201).json({ status: 201, storeData });
    }
  } catch (error) {
    res.status(422).json(error);
    console.log("catch block error");
  }
});

router.post("/login", async (req, res) => {
  console.log(req.body);

  const { email, password } = req.body;

  if (!email || !password) {
    res.status(422).json({ error: "fill all the details" });
  }

  try {
    const userValid = await userdb.findOne({ email: email });

    if (userValid) {
      const isMatch = await bcrypt.compare(password, userValid.password);

      if (!isMatch) {
        res.status(422).json({ error: "invalid details" });
      } else {
        // token generate
        const token = await userValid.generateAuthtoken();

        // cookiegenerate
        res.cookie("usercookie", token, {
          expires: new Date(Date.now() + 9000000),
          httpOnly: true,
        });

        const result = {
          userValid,
          token,
        };
        res.status(201).json({ status: 201, result });
      }
    } else {
      res.status(401).json({ status: 401, message: "invalid details" });
    }
  } catch (error) {
    res.status(401).json({ status: 401, error });
    console.log("catch block");
  }
});

// verify user for forgot password time
router.get("/forgotpassword/:id/:token", async (req, res) => {
  const { id, token } = req.params;

  try {
    const validuser = await userdb.findOne({ _id: id, verifytoken: token });

    const verifyToken = jwt.verify(token, keysecret);

    console.log(verifyToken);

    if (validuser && verifyToken._id) {
      res.status(201).json({ status: 201, validuser });
    } else {
      res.status(401).json({ status: 401, message: "user not exist" });
    }
  } catch (error) {
    res.status(401).json({ status: 401, error });
  }
});

router.post("/:id/:token", async (req, res) => {
  const { id, token } = req.params;
  const { password } = req.body;

  try {
    const validuser = await userdb.findOne({ _id: id, verifytoken: token });

    if (validuser) {
      try {
        const verifyToken = jwt.verify(token, keysecret);

        if (verifyToken && verifyToken._id === id) {
          const newpassword = await bcrypt.hash(password, 12);

          const setnewuserpass = await userdb.findByIdAndUpdate(id, {
            password: newpassword,
          });

          res
            .status(201)
            .json({ status: 201, message: "Password reset successful" });
        } else {
          res.status(401).json({ status: 401, message: "Invalid token" });
        }
      } catch (error) {
        console.error(error);
        res.status(401).json({ status: 401, message: "Invalid token" });
      }
    } else {
      res.status(401).json({ status: 401, message: "User not found" });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ status: 500, message: "Internal server error" });
  }
});

// change password

router.post("/:id/:token", async (req, res) => {
  const { id, token } = req.params;

  const { password } = req.body;

  try {
    const validuser = await userdb.findOne({ _id: id, verifytoken: token });

    const verifyToken = jwt.verify(token, keysecret);

    if (validuser && verifyToken._id) {
      const newpassword = await bcrypt.hash(password, 12);

      const setnewuserpass = await userdb.findByIdAndUpdate(
        { _id: id },
        { password: newpassword }
      );

      setnewuserpass.save();
      res.status(201).json({ status: 201, setnewuserpass });
    } else {
      res.status(401).json({ status: 401, message: "user not exist" });
    }
  } catch (error) {
    res.status(401).json({ status: 401, error });
  }
});

// send email Link For reset Password
router.post("/sendpasswordlink", async (req, res) => {
  console.log(req.body);

  const { email } = req.body;

  if (!email) {
    res.status(401).json({ status: 401, message: "Enter Your Email" });
  }

  try {
    const userfind = await userdb.findOne({ email: email });

    // token generate for reset password
    const token = jwt.sign({ _id: userfind._id }, keysecret, {
      expiresIn: "120s",
    });

    const setusertoken = await userdb.findByIdAndUpdate(
      { _id: userfind._id },
      { verifytoken: token },
      { new: true }
    );

    if (setusertoken) {
      const mailOptions = {
        from: process.env.EMAIL,
        to: email,
        subject: "Sending Email For password Reset",
        text: `This Link Valid For 2 MINUTES http://localhost:3000/forgotpassword/${userfind.id}/${setusertoken.verifytoken}`,
      };

      transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
          console.log("error", error);
          res.status(401).json({ status: 401, message: "email not send" });
        } else {
          console.log("Email sent", info.response);
          res
            .status(201)
            .json({ status: 201, message: "Email sent Succsfully" });
        }
      });
    }
  } catch (error) {
    res.status(401).json({ status: 401, message: "invalid user" });
  }
});

module.exports = router;
