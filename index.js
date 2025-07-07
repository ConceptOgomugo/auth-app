import express from "express";
import pg from "pg";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

const app = express();
const port = 3000;
const saltRounds = 10;

app.use(express.urlencoded({ extended: true }));
app.use(express.static("public"));

import dotenv from 'dotenv';
dotenv.config();

import pkg from 'pg';
const { Pool } = pkg;

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false } // Required by Render
});

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM admin_user WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      // Hash the password
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.error("Error hashing password:", err);
          res.status(500).send("Internal error");
        } else {
          console.log("Hashed Password:", hash);

          // Save to DB
          await db.query(
            "INSERT INTO admin_user (email, password) VALUES ($1, $2)",
            [email, hash]
          );


          // ✅ Redirect to main app with token in query param
          res.redirect(`https://main-app-qq2y.onrender.com`);
        }
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM admin_user WHERE email = $1", [
      email,
    ]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashedPassword = user.password;

      // Verifying the password
      bcrypt.compare(loginPassword, storedHashedPassword, (err, isMatch) => {
        if (err) {
          console.error("Error comparing passwords:", err);
          res.status(500).send("Server error");
        } else {
          if (isMatch) {
            // ✅ Create the token
            const token = jwt.sign({ email }, process.env.JWT_SECRET, {
              expiresIn: "1h",
            });

            // ✅ Redirect to main app with the token
            res.redirect(`https://main-app-qq2y.onrender.com/?token=${token}`);
          } else {
            res.send("Incorrect password");
          }
        }
      });
    } else {
      res.send("User not found");
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Server error");
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
