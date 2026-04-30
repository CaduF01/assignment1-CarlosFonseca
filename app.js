require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');

const { database } = require('./databaseConnection');

const app = express();
const PORT = process.env.PORT || 3000;
const saltRounds = 12;
const expireTime = 60 * 60 * 1000; // 1 hour in ms

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

// dbName must be set explicitly (big prablem) connect-mongo ignores the database in the URL path
// and defaults to "test" otherwise shi cooked me up.
const mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`,
    dbName: mongodb_database,
    crypto: { secret: mongodb_session_secret }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
    cookie: { maxAge: expireTime }
}));

function isAuthenticated(req) {
    return req.session && req.session.authenticated;
}

// Home
app.get('/', (req, res) => {
    if (isAuthenticated(req)) {
        res.send(`
            <h1>Hello, ${req.session.name}!</h1>
            <a href="/members"><button>Go to Members Area</button></a>
            <br><br>
            <a href="/logout"><button>Logout</button></a>
        `);
    } else {
        res.send(`
            <a href="/signup"><button>Sign up</button></a>
            <br><br>
            <a href="/login"><button>Log in</button></a>
        `);
    }
});

// Signup form
app.get('/signup', (req, res) => {
    res.send(`
        <h3>create user</h3>
        <form action="/signupSubmit" method="post">
            <input name="name" type="text" placeholder="name"><br>
            <input name="email" type="text" placeholder="email"><br>
            <input name="password" type="password" placeholder="password"><br>
            <button>Submit</button>
        </form>
    `);
});

// Signup submit
app.post('/signupSubmit', async (req, res) => {
    const { name, email, password } = req.body;

    if (!name) {
        res.send(`<p>Name is required.</p><a href="/signup">Try again</a>`);
        return;
    }
    if (!email) {
        res.send(`<p>Email is required.</p><a href="/signup">Try again</a>`);
        return;
    }
    if (!password) {
        res.send(`<p>Password is required.</p><a href="/signup">Try again</a>`);
        return;
    }

    const schema = Joi.object({
        name: Joi.string().max(50).required(),
        email: Joi.string().email({ tlds: { allow: false } }).max(100).required(),
        password: Joi.string().max(50).required()
    });

    const validationResult = schema.validate({ name, email, password });
    if (validationResult.error) {
        res.send(`<p>Invalid input: ${validationResult.error.details[0].message}</p><a href="/signup">Try again</a>`);
        return;
    }

    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await userCollection.insertOne({ name, email, password: hashedPassword });

    req.session.authenticated = true;
    req.session.name = name;
    req.session.save(() => res.redirect('/members'));
});

// Login form
app.get('/login', (req, res) => {
    res.send(`
        <h3>log in</h3>
        <form action="/loginSubmit" method="post">
            <input name="email" type="text" placeholder="email"><br>
            <input name="password" type="password" placeholder="password"><br>
            <button>Submit</button>
        </form>
    `);
});

// Login submit
app.post('/loginSubmit', async (req, res) => {
    const { email, password } = req.body;

    const schema = Joi.object({
        email: Joi.string().email({ tlds: { allow: false } }).max(100).required(),
        password: Joi.string().max(50).required()
    });

    const validationResult = schema.validate({ email, password });
    if (validationResult.error) {
        res.send(`<p>Invalid email/password combination.</p><a href="/login">Try again</a>`);
        return;
    }

    const result = await userCollection
        .find({ email })
        .project({ name: 1, email: 1, password: 1, _id: 1 })
        .toArray();

    if (result.length !== 1) {
        res.send(`<p>Invalid email/password combination.</p><a href="/login">Try again</a>`);
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        req.session.authenticated = true;
        req.session.name = result[0].name;
        req.session.save(() => res.redirect('/members'));
        return;
    }

    res.send(`<p>Invalid password.</p><a href="/login">Try again</a>`);
});

// Members
const memberImages = ['image1.png', 'image2.png', 'image3.png'];

app.get('/members', (req, res) => {
    if (!isAuthenticated(req)) {
        res.redirect('/');
        return;
    }
    const randomImage = memberImages[Math.floor(Math.random() * memberImages.length)];
    res.send(`
        <h1>Hello, ${req.session.name}.</h1>
        <img src="/${randomImage}" style="width:250px;">
        <br>
        <a href="/logout"><button>Sign out</button></a>
    `);
});

// Logout
app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

// Static files
app.use(express.static(__dirname + '/public'));

// 404
app.use((req, res) => {
    res.status(404);
    res.send('Page not found - 404');
});

app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
