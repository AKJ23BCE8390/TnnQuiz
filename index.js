import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcryptjs";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import GoogleStrategy from "passport-google-oauth2";
import session from "express-session";
import env from "dotenv";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
  })
);
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.PG_USER,
  host: process.env.PG_HOST,
  database: process.env.PG_DATABASE,
  password: process.env.PG_PASSWORD,
  port: process.env.PG_PORT,
});
db.connect();

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/login");
}

app.get("/", (req, res) => {
  res.render("quiz.ejs");
});

app.get("/club", (req, res) => {
  res.render("club.ejs");
});

app.get("/quiz", (req, res) => {
  res.render("quiz.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/signup", (req, res) => {
  res.render("signup.ejs");
});

app.get("/contact", (req, res) => {
  res.render("contact.ejs");
});

app.get("/start-quiz", (req, res) => {
  res.render("quizzes.ejs");
});

app.get("/admin", (req,res)=>{
  res.render("admin.ejs");
})

app.get("/logout", (req, res) => {
  req.logout(function (err) {
    if (err) {
      return next(err);
    }
    res.redirect("/quiz");
  });
});

app.get("/dashboard", ensureAuthenticated, async (req, res) => {
  try {
    const result = await db.query("SELECT name FROM users WHERE email = $1", [req.user.email]);
    if (result.rows.length > 0) {
      const name = result.rows[0].name;
      res.render("dashboard.ejs", { name: name || "name" });
    } else {
      res.redirect("/login");
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Server Error");
  }
});

app.get('/admin/manage-quizzes', ensureAuthenticated, async (req, res) => {
  try {
    const result = await db.query('SELECT * FROM quizzes');
    const quizzes = result.rows;
    res.render('manage-quizzes.ejs', { quizzes });
  } catch (err) {
    console.error('Error fetching quizzes:', err);
    res.send('Error loading quizzes.');
  }
});

app.post('/admin/create-quiz', ensureAuthenticated, async (req, res) => {
  const { title, description, num_questions, time_limit } = req.body;
  try {
    await db.query(
      'INSERT INTO quizzes (title, description, num_questions, time_limit) VALUES ($1, $2, $3, $4)',
      [title, description, num_questions, time_limit]
    );
    res.redirect('/admin/manage-quizzes');
  } catch (err) {
    console.error('Error creating quiz:', err);
    res.send('Error creating quiz.');
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/dashboard",
  passport.authenticate("google", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/dashboard",
    failureRedirect: "/login",
  })
);

app.post("/register", async (req, res) => {
  const { name, email, password, confirm_password } = req.body;

  // Check if passwords match
  if (password !== confirm_password) {
    return res.render("signup.ejs", { message: "Passwords do not match." });

  }

  try {
    // Check if email already exists
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);

    if (checkResult.rows.length > 0) {
      res.redirect("/login");
    } else {
      // Hash password and save new user
      const hash = await bcrypt.hash(password, saltRounds);
      const result = await db.query(
        "INSERT INTO users (name, email, password) VALUES ($1, $2, $3) RETURNING *",
        [name, email, hash]
      );
      const user = result.rows[0];
      console.log(user);

      // Log the user in automatically after registration
      req.login(user, (err) => {
        if (err) throw err;
        res.redirect("/dashboard");  // Redirect to dashboard
      });
    }
  } catch (err) {
    console.log(err);
    res.status(500).send("Server Error");
  }
});


passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [username]);
      if (result.rows.length > 0) {
        const user = result.rows[0];
        const valid = await bcrypt.compare(password, user.password);
        return done(null, valid ? user : false);
      } else {
        return done(null, false, { message: "User not found" });
      }
    } catch (err) {
      return done(err);
    }
  })
);

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/dashboard",
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [profile.email]);
        if (result.rows.length === 0) {
          const newUser = await db.query(
            "INSERT INTO users (name, email, password) VALUES ($1, $2, $3)",
            [profile.displayName, profile.email, "google"]
          );
          return done(null, newUser.rows[0]);
        } else {
          return done(null, result.rows[0]);
        }
      } catch (err) {
        return done(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err);
  }
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send("Something went wrong!");
});

