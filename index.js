import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy } from "passport-local";
import env from "dotenv";
import GoogleStrategy from "passport-google-oauth2";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
//save user login during session
app.use(
  session({
    //key used to keep the session secret
    secret: process.env.SESSION_SECRET,
    //save session to database?
    resave: false,
    //save to server memory
    saveUninitialized: true,
    cookie: {
      //one day
      maxAge: 1000 * 60 * 60 * 24,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  database: process.env.DB_DATABASE,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
});

db.connect();

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", (req, res) => {
  //show right away with an active session cookie
  console.log(req.user);
  if (req.isAuthenticated()) {
    res.render("secrets.ejs");
  } else {
    res.redirect("/login");
  }
});

app.post("/register", async (req, res) => {
  const { username: email, password } = req.body;

  //use try catch in case of database not working etc
  try {
    //check if email already exists
    const checkEmail = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    //if exists -> error
    if (checkEmail.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      //else add password and email to database with hash
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing password: ", err);
        } else {
          const result = await db.query(
            "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING * ;",
            [email, hash]
          );
          const user = result.rows[0];
          req.login(user, (err) => {
            if (err) {
              console.log(err);
            } else {
              res.redirect("/secrets");
            }
          });
        }
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"],
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get("/logout", (req,res) => {
  req.logout((err) => {
    if(err) console.log(err)
    res.redirect("/")
  })
})

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

passport.use(
  new Strategy(async function verify(username, password, cb) {
    //if user exists check if password corresponds
    try {
      const checkEmail = await db.query(
        "SELECT * FROM users WHERE email = $1",
        [username]
      );

      if (checkEmail.rows.length > 0) {
        const user = checkEmail.rows[0];
        const storedPassword = user.password;
        //check if encrypted passwords match
        bcrypt.compare(password, storedPassword, (err, result) => {
          if (err) {
            cb(err);
          } else {
            if (result) {
              return cb(null, user);
            } else {
              return cb(null, false);
            }
          }
        });
      } else {
        return cb("User not found");
      }
    } catch (error) {
      return cb(err);
    }
    //if match send to secrets page
    //if not tell them no match
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo",
    },
    async (accessToken, refreshToken, profile, cb) => {
      console.log(profile);
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile.email,
        ]);
        if (result.rows.length === 0) {
          await db.query("INSERT INTO users (email, password) VALUES ($1,$2)", [
            profile.email,
            "google",
          ]);
          cb(null, user);
        }else{
          cb(null, result.rows[0])
        }
      } catch (error) {
        cb(error)
      }
    }
  )
);

// save data of logged in user to local storage
passport.serializeUser((user, cb) => {
  cb(null, user);
});

//saves users info to local session and if you want to get a hold of the user it deserializes it
passport.deserializeUser((user, cb) => {
  cb(null, user);
});
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
