const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const app = express();
const port = 3000;
const jwtSecret = 'your_jwt_secret';

app.use(bodyParser.json());

// Connect to MongoDB
mongoose.connect('mongodb://localhost/elearning', { useNewUrlParser: true, useUnifiedTopology: true });

const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);

// Middleware to authenticate and verify JWT
const authenticateJWT = (req, res, next) => {
    const token = req.header('Authorization').split(' ')[1];
    if (token) {
        jwt.verify(token, jwtSecret, (err, user) => {
            if (err) {
                return res.sendStatus(403);
            }
            req.user = user;
            next();
        });
    } else {
        res.sendStatus(401);
    }
};

// Register route
app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ username, password: hashedPassword });
    await user.save();

    res.status(201).send('User registered');
});

// Login route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    const user = await User.findOne({ username });

    if (user && await bcrypt.compare(password, user.password)) {
        const accessToken = jwt.sign({ username: user.username }, jwtSecret);
        res.json({ accessToken });
    } else {
        res.send('Username or password incorrect');
    }
});

// Protected route
app.get('/protected', authenticateJWT, (req, res) => {
    res.send('This is a protected route');
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}/`);
});
