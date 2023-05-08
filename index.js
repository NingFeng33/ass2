require("./units.js");

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;
const port = process.env.PORT || 8080;
const app = express();
const Joi = require('joi');
const {ObjectId} = require('mongodb');

const expireTime = 1 * 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const images = [
	"pic1.png",
	"pic2.png",
	"pic3.png",
  ];

var {database} = include('databaseConnection');
app.set('view engine', 'ejs');
const userCollection = database.db(mongodb_database).collection('users');
app.use(express.json());
app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	    crypto: {
			     secret: mongodb_session_secret
		}
});

app.use(session({
	    secret: node_session_secret,
	        store: mongoStore,
	        saveUninitialized: false,
			resave: true,
}
));

function isValidSession(req) {
	if (req.session.authenticated) {
	  return true;
	}
	return false;
  }
  
  function sessionValidation(req, res, next) {
	if (isValidSession(req)) {
	  next();
	} else {
	  res.redirect("/login");
	}
  }
  
  function isAdmin(req) {
	if (req.session.user_type == "admin") {
	  return true;
	}
	return false;
  }
  
  function adminAuthorization(req, res, next) {
	if (!isAdmin(req)) {
	  res.status(403);
	  res.render("errorMessage", { error: "Not Authorized" });
	  return;
	} else {
	  next();
	}
  }

  app.get("/", (req, res) => {
	if (req.session.username) {
	  const mypic = req.query.mypic;
	  res.render("members", {
		images: images,
		username: req.session.username,
		mypic: mypic,
	  });
	} else {
	  res.render("index");
	}
  });

  app.get("/members", function (req, res) {
	if (req.session.username) {
	  const mypic = req.query.mypic;
	  res.render("members", {
		images: images,
		username: req.session.username,
		mypic: mypic,
	  });
	} else {
	  res.redirect("/");
	}
  });

  app.post("/members", async (req, res) => {
	const username = req.session.username;
	res.render("members", { username: username, images: images });
  });

app.get('/nosql-injection', async (req,res) => {
	var username = req.query.user;

	if (!username) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("user: "+username);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

app.get("/createUser", (req, res) => {
	res.render("createUser");
  });

app.get("/login", (req, res) => {
	res.render("login");
  });


  app.post("/submitUser", async (req, res) => {
	var username = req.body.username;
	var email = req.body.email;
	var password = req.body.password;
  
	const schema = Joi.object({
	  username: Joi.string().alphanum().max(20).required(),
	  email: Joi.string().email().max(20).required(),
	  password: Joi.string().max(20).required(),
	});
  
	const validationResult = schema.validate({ username, email, password });
	if (validationResult.error != null) {
	  console.log(validationResult.error);
	  res.render("errorMessage", { error: "Invalid input." });
	  return;
	}
  
	var hashedPassword = await bcrypt.hash(password, saltRounds);
  
	await userCollection.insertOne({
	  username: username,
	  email: email,
	  password: hashedPassword,
	  user_type: "user",
	});
	req.session.authenticated = true;  
    req.session.email = email; 
    req.session.username = username;
	console.log("Inserted user");
  
	res.redirect("/members");
  });


app.post('/loggingin', async (req,res) => {
    var username = req.body.username;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(username);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.render("errorMessage", { error: "Invalid input." });
	   return;
	}

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1, user_type: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.render("errorMessage", { error: "User not found." });
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.username = username;
		req.session.user_type = result[0].user_type;
		req.session.cookie.maxAge = expireTime;
		console.log("User type:", result[0].user_type);
		res.redirect("/members");
		return;
	}
	else {
		console.log("incorrect password");
		res.render("errorMessage", {
			error: "Incorrect password.",
		  });
		  return;
	}
	
});

app.use("/loggedin", sessionValidation);
app.get('/loggedin', (req,res) => {
    if (!req.session.authenticated) {
        res.redirect('/login');
    }
    res.render("loggedin");
});

app.get('/logout', function (req,res) {
	req.session.destroy(function (err) {
		if (err) {
		  console.log(err);
		} else {
		  res.redirect("/");
		}
	  });
	});

app.get('/pic/:id', (req, res) => {

	var pic = req.params.id;
		res.render("mypic", { mypic: pic });
  });

//   app.get("/admin", async (req, res) => {
// 	if (!req.session.authenticated || req.session.user_type !== "admin") {
// 	  res.redirect("/");
// 	  return;
// 	}
  
// 	const result = userCollection
// 	  .find({ email: { $ne: req.session.email } })
// 	  .project({ name: 1, _id: 1, user_type: 1 });
// 	const users = await result.toArray();
// 	res.render("admin", { users: users });
//   });

  app.get("/admin", sessionValidation, adminAuthorization, async (req, res) => {
	const result = await userCollection
	  .find()
	  .project({ username: 1, _id: 1, user_type: 1 })
	  .toArray();
  
	res.render("admin", { users: result });
  });
  


  app.post("/admin/promote", async (req, res) => {
	const { userId } = req.body;
	console.log(req.body)
	await userCollection.updateOne(
	  { _id: new ObjectId(userId) },
	  { $set: { user_type: "admin" } }
	);
	res.redirect("/admin");
  });
  
  app.post("/admin/demote", async (req, res) => {
	const { userId } = req.body;
	await userCollection.updateOne(
	  { _id: new ObjectId(userId) },
	  { $set: { user_type: "user" } }
	);
	res.redirect("/admin");
  });

app.post('/promote', async (req, res) => {
    const {userId} = req.body;
    const newRole = req.body.role;
    console.log(userId);
    console.log(newRole);
    const ObjectId = require('mongodb').ObjectId;
    try {
      await userCollection.updateOne({  _id: new ObjectId(userId) }, { $set: { user_type: newRole } });
      res.redirect('/admin');
    } catch (err) {
      console.log(err);
      res.status(500).send('Error promoting user');
    }
  });

app.post('/signout', (req, res) => {
	// clear session and redirect to signup page
	req.session.destroy(() => {
	  res.redirect('/');
	});
  });

app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.render("404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 
