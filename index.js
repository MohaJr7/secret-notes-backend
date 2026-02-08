import express from "express";
import db from "./db.js";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import dotenv from "dotenv";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

/* ---------------- Middleware ---------------- */

app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static("public"));
app.set("view engine", "ejs");

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
  })
);

app.use(passport.initialize());
app.use(passport.session());

/* ---------------- Passport ---------------- */

passport.use(
  new LocalStrategy({ usernameField: "email" }, async (email, password, done) => {
    try {
      const result = await db.query(
        "SELECT * FROM users WHERE email = $1",
        [email]
      );

      if (result.rows.length === 0) {
        return done(null, false, { message: "User not found" });
      }

      const user = result.rows[0];
      const valid = await bcrypt.compare(password, user.password);

      return valid ? done(null, user) : done(null, false);
    } catch (err) {
      done(err);
    }
  })
);

passport.serializeUser((user, done) => done(null, user.id));

passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err);
  }
});

/* ---------------- Helpers ---------------- */

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

/* ---------------- Routes ---------------- */

app.get("/", (req, res) => {
  res.render("index");
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.get("/register", (req, res) => {
  res.render("register");
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

/* -------- Register -------- */

app.post("/register", async (req, res) => {
  const { email, password } = req.body;

  try {
    const existingUser = await db.query(
      "SELECT * FROM users WHERE email = $1",
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.redirect("/login");
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);

    const result = await db.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
      [email, hashedPassword]
    );

    req.login(result.rows[0], () => {
      res.redirect("/notes");
    });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    res.status(500).send("Registration failed");
  }
});

/* -------- Login -------- */

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/notes",
    failureRedirect: "/login",
  })
);

/* -------- Protected Routes -------- */

app.get("/notes", ensureAuthenticated, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT * FROM notes WHERE user_id = $1",
      [req.user.id]
    );

    res.render("notes.ejs", { notes: result.rows });
  } catch (err) {
    console.error("NOTES ERROR:", err);
    res.status(500).send("Database not ready");
  }
});

app.post("/notes", ensureAuthenticated, async (req, res) => {
  const { title, content } = req.body;

  try {
    await db.query(
      "INSERT INTO notes (user_id, title, content) VALUES ($1, $2, $3)",
      [req.user.id, title, content]
    );

    res.redirect("/notes");
  } catch (err) {
    console.error("SAVE NOTE ERROR:", err);
    res.status(500).send("Error saving note");
  }
});



/* ---------------- Server ---------------- */

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
