import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";

const app = express();
const port = 3000;
const saltRounds = 10;

const db = new pg.Client({
  user: "postgres",
  host: "localhost",
  database: "secrets",
  password: "password1234",
  port: 5432,
});

db.connect();

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
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
            "INSERT INTO users (email, password) VALUES ($1, $2);",
            [email, hash]
          );
          res.render("secrets.ejs");
        }
      });
    }
  } catch (error) {
    console.log(error);
  }
});

app.post("/login", async (req, res) => {
  const { username: email, password: loginPassword } = req.body;
  //if user exists check if password corresponds
  try {
    const checkEmail = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkEmail.rows.length > 0) {
      const storedPassword = checkEmail.rows[0].password
      //check if encrypted passwords match
      bcrypt.compare(loginPassword, storedPassword, (err, result) => {
        if(err){
          console.log(err)
        }else{
          if(result){
            res.render("secrets.ejs");
          }else{
            res.send("Password does not match");
          }
        }
      })
    } else {
      res.send("User not found");
    }
  } catch (error) {
    console.log(error);
  }
  //if match send to secrets page
  //if not tell them no match
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
