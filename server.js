// Import Depends.
var bcrypt = require('bcryptjs');
var bodyParser = require('body-parser');
var csrf = require('csurf');
var express = require('express');
var mongoose = require('mongoose');
var sessions = require('client-sessions');

//Create mongoose dynamic schema
var Schema = mongoose.Schema;
var ObjectId = Schema.ObjectId;

// connect to Mongodb
mongoose.connect('mongodb://admin:admin123@ds059365.mlab.com:59365/guru99');

// Create mongoose model
var User = mongoose.model('User', new Schema({
    id: ObjectId,
    firstName: String,
    lastName: String,
    email: { type: String, unique: true },
    password: String
}));

//Setup app & view engine
var app = express();
app.set('view engine', 'jade');
app.locals.pretty = true;

//middleware
app.use(bodyParser.urlencoded({extended: true}));
app.use(csrf());
app.use(sessions({
    cookieName: 'session',
    secret: 'hfkuedfnhdfhddjkdjdjhfjkdkjdh',
    duration: 30 * 60 * 1000,
    activeDuration: 5 * 60 * 1000,
    httpOnly: true,
    secure: true,
    ephemeral: true
}));

app.use(function(req, res, next){
    if(req.session && req.session.user)
        User.findOne({ email: req.session.user.email }, function (err, user){
        if (user){
            req.user = user;
            delete  req.user.password;
            req.session.user = user;
            req.locals.user = user;
        }
        next();
    }); else next();
});

function requiredLogin(req, res, next){
    if(!req.user){
        res.redirect('/login');
    } else next();
}
// Get Routes
app.get('/', function (req, res) {
    res.render('index.jade');
});

app.get('/login', function (req, res) {
    res.render('login.jade', { csrfToken: req.csrfToken() });
});

app.get('/register', function (req, res) {
    res. render('register.jade', { csrf: req.csrfToken() });
});

app.get('/dashboard', requiredLogin, function (req, res) {
    res.render('/dashboard.jade');
});

app.get('/logout', function (req, res) {
    res.redirect('/');
});

//Create and save a user
app.post('/register', function (req, res) {
    var salt = bcrypt.genSaltSync(10);
    var hash = bcrypt.hashSync(req.body.password, salt);
    var user = new User({
        firstName: req.body.firstName,
        lastName: req.body.lastName,
        email: req.body.email,
        password: hash
    });
    user.save(function (err) {
        if (err) {
            var error = 'Something bad happened! Please Try again.';
            if (err.code === 11000) {
                error = 'That email is already taken, try another email.';
            }
            res.render('register.jade', {error: error});
        } else {
            req.session.user = user.email;
            res.redirect('/dashboard');
        }
    });
});

// Logging in the user Sessions
app.post('/login', function (req, res) {
    User.findOne({email: req.body.email}, function (err, user) {
        if (!user) res.render('login.jade', {error: 'Invalid email or password.'}); else {
            if (bcrypt.compareSync(req.body.password, user.password)){
                res.session.user = user.email;
                res.redirect('/dashboard');
            } else {
                res.render('login.jade', {error: 'Incorrect email or password,'});
            }
        }
    });
});

app.listen(3000);
console.log('server running on port 3000');
