require('dotenv').config();//keeps the secrets hidden
const express = require('express');
const bodyParser = require('body-parser');
const ejs = require('ejs');
const mongoose = require('mongoose');
const flash = require('express-flash')
const session = require('express-session');
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const rateLimit = require('express-rate-limit');

const MongoClient = require('mongodb').MongoClient;

const auditLog = require('audit-log');
const app = express();
const https = require('https');
const http = require('http')
const fs = require("fs");
const initializePassport = require('./passport-config')

//audit-log in MongoDb, logs users activity
auditLog.addTransport("mongoose", {connectionString: "mongodb://localhost/auditdb"})

const PORT = process.env.PORT || 3000
const uri = process.env.MONGODB;

//certificate, secret keys to SSL wich allows communication between server and client (browser)
const options = {
    key: fs.readFileSync('../razvans-key.pem'),
    cert: fs.readFileSync('../razvans-cert.pem')
}; 

//monitoring links to healtcheck route to watch over our app and warn us if an attack is coming
app.use('/healthcheck', require('./routes/healthcheck.routes'));

app.use(express.static('public')); //css files
app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({
    extended: true
}));

//cookie to be saved in session storage
app.use(session({
    secret:process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: { secure: true }
}));

app.use(passport.initialize());//passport starts encryption
app.use(passport.session());//passport starts encryption and cookies stops



//connection to MongoDB thru defaultport
//if the user registers with Google we can only see Google Id and submitted secret otherwise we can see encrypted password and secret
mongoose.connect("mongodb://localhost:27017/userDB", {useNewUrlParser: true});

//structure to be send to database
const userSchema = new mongoose.Schema ({
    email: String,
    password: String,
    googleId: String,
    secret: String
});

//encryption
userSchema.plugin(passportLocalMongoose);//encrypts the users password
userSchema.plugin(findOrCreate);//finds the user with google id or creates one if the user doesn't exists

//creates new user in database
const User = new mongoose.model("User", userSchema);

//authentificate the user
passport.use(User.createStrategy());

//serialize encrypts the cookie with users id
passport.serializeUser(function(user, done){
    done(null, user.id)
});

//decrypts the cookie so we can identify the user
passport.deserializeUser(function (id, done) {
    User.findById(id, function(err, user){
        done(err, user);
    });
});

//encryption, passport google oauth
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID, //links to .env where we have the client id and secrets
    clientSecret: process.env.CLIENT_SECRET, //link to .env
    callbackURL: "http://localhost:3000/auth/google/secretapp",//connecting with google
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"//connecting with google
},
  
//authorize, google sends accestoken so that we can use the data as long as we need to
  function(accessToken, refreshToken, profile, cb) {
      console.log(profile)
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// access logging limits the loggin tryes to 10 times in 15 minutes from the same IP address
const createLimiter = rateLimit({
	windowMs: 15 * 60 * 1000, // 15 minutes
	max: 10, //10 tryes
	message: "Too many accounts created from this IP, please try again after 15 minutes", 
    standardHeaders: true,// shows how many tryes you have left to login
	legacyHeaders: false,
});

const limiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 10,
	message: "Too many requests sent from this IP, please try again after 15 minutes",
    standardHeaders: true, 
	legacyHeaders: false, 
});


/* ### ALL THE ROUTES ### */

app.get('/',limiter, function(req,res){
    res.render('home')
});

// passport authentification with google
app.get('/auth/google',
    passport.authenticate('google', { scope: ['profile'] })
);

// google authentificate the use locally and send him to the secrets page
app.get('/auth/google/secretapp', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

// limits the login and register sumbmit routes
app.get('/login',limiter, function(req,res){
    res.render('login')
});

app.get('/register',createLimiter, function(req,res){
    res.render('register')
});

// send the user to terms&conditions page
app.get('/terms', function(req, res){
    res.render('terms')
});

// displays all the secrets (annonymously)
app.get('/secrets', function (req, res){
    User.find({'secret': {$ne: null}}, function(err, foundUsers){
        if(err){
            console.log(err)
        } else {
            if(foundUsers) {
                res.render('secrets', {usersWithSecrets: foundUsers});
            }
        }
    });
});

// if the user is not logged in is sent to login page first and then he can submit a secret
app.get('/submit', function (req,res) {
    if(req.isAuthenticated()){
        res.render('submit')
    }else {
        res.redirect('/login');
    }
});

// secret is saved with the user ID,
// every new user has a secret
app.post('/submit', function(req, res) {
    const submittedSecret = req.body.secret;
     // finds user by ID
    User.findById(req.user.id, function(err, foundUser){
        if (err) {
            console.log(err)
        } else {
            if(foundUser) {
                foundUser.secret = submittedSecret;
                foundUser.save(function(){
                    res.redirect('/secrets');
                });
            }
            auditLog.logEvent(foundUser.username, 'maybe script name or function',
            "submitted a secret", foundUser.secret, 'target id', 'additional info, JSON, etc.');
        }
    });
});

// user log out
app.get('/logout', function(req, res, next) {
    req.logout();
      req.session = null; //tar bort cookie
      res.redirect('/');
  });

// if login is ok, the user has access to secrets, otherwhise he is stuck on register page
// registers new users 
app.post('/register',(req,res)=>{
 
    User.register({username: req.body.username}, req.body.password, function(err, user){
        if(err){
            console.log(err);
            res.redirect('/register');
        } else {
            passport.authenticate('local')(req, res, function(){
                res.redirect('/login');
            });
        }
    });
});


// verify so that the user and password match with passport
app.post('/login', function(req, res){
    const user = new User({
        username: req.body.username,
        password: req.body.password
    });
    auditLog.logEvent(user.username, 'maybe script name or function',
    "tried to log in", 'the affected target name perhaps', 'target id', 'additional info, JSON, etc.');
    
    req.login(user, function(err){
        if(err){
            console.log(err);
            res.redirect('/login');
        } else{
            passport.authenticate('local')(req, res, function(){
                res.redirect('/secrets');
            });
        }
    });
});

//Acesslogging , Touring Test
function recaptcha_callback() {
    var loginBtn = document.querySelector('#login-btn');
    loginBtn.removeAttribute('disabled');
    loginBtn.style.cursor = 'pointer';
}

/*
app.listen(PORT, () =>  {
    console.log('info', `STARTED LISTENING ON PORT ${PORT}`);
});
*/

// SLL server
http.createServer(app).listen(PORT, function(){
  console.log('info', `STARTED LISTENING ON PORT ${PORT}`);
});

https.createServer(options, app).listen(443, function(){
  console.log('HTTPS listening on 443');
});
