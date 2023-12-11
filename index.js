

const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const nodemailer = require('nodemailer');
const cors = require('cors')
const PORT = process.env.PORT || 5000;
const app = express();

// MySQL connection 
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'users'
});

db.connect((err) => {
    if (err) {
        console.error('Error connecting to MySQL:', err);
    } else {
        console.log('Connected to MySQL');
    }
});

app.use(bodyParser.json());
app.use(cors())
app.use(express.json())

// JWT secret key
const secretKey = '12345';

// Nodemailer setup
const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'your_email@gmail.com',
        pass: 'your_email_password',
    },
});

// Middleware to verify JWT token
function verifyToken(req, res, next) {
    const token = req.headers['authorization'];

    if (!token) {
        return res.status(403).send({ auth: false, message: 'No token provided.' });
    }

    jwt.verify(token, secretKey, (err, decoded) => {
        if (err) {
            return res.status(500).send({ auth: false, message: 'Failed to authenticate token.' });
        }

        req.userId = decoded.id;
        next();
    });
}

// Signup route
app.post('/signup', async (req, res) => {
    const { username, password, email } = req.body;

    // Hash the password before storing it in the database
    const hashedPassword = await bcrypt.hash(password, 10);

    const sql = 'INSERT INTO users (username, password, email) VALUES (?, ?, ?)';
    const values = [username, hashedPassword, email];

    db.query(sql, values, (err, result) => {
        if (err) {
            console.error('Error signing up:', err);
            res.status(500).json({msg : 'Error signing up.', success : false});
        } else {
            res.status(200).json({msg : 'User signed up successfully.', success : true});
        }
    });
});

// Login route
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    const sql = 'SELECT * FROM users WHERE email = ?';
    const values = [email];

    db.query(sql, values, async (err, results) => {
        if (err) {
            console.error('Error logging in:', err);
            res.status(500).send('Error logging in.');
        } else {
            if (results.length > 0) {
                const user = results[0];
                const passwordMatch = await bcrypt.compare(password, user.password);

                if (passwordMatch) {
                    // Generate JWT token
                    const token = jwt.sign({ id: user.id }, secretKey, { expiresIn: 86400 }); // Expires in 24 hours

                    res.status(200).send({ auth: true, token });
                } else {
                    res.status(401).send({msg : 'Invalid password.'});
                }
            } else {
                res.status(404).send('User not found.');
            }
        }
    });
});

// Forgot password route
app.post('/forgot-password', (req, res) => {
    const { email } = req.body;

    const sql = 'SELECT * FROM users WHERE email = ?';
    const values = [email];

    db.query(sql, values, (err, results) => {
        if (err) {
            console.error('Error retrieving user:', err);
            res.status(500).send('Error retrieving user.');
        } else {
            if (results.length > 0) {
                const user = results[0];

                // Generate a temporary token for password reset
                const resetToken = jwt.sign({ id: user.id }, secretKey, { expiresIn: 600 }); // Expires in 10 minutes

                // Send email with reset link
                const mailOptions = {
                    from: 'your_email@gmail.com',
                    to: user.email,
                    subject: 'Password Reset',
                    text: `Click the following link to reset your password: http://yourfrontendapp.com/reset-password?token=${resetToken}`,
                };

                transporter.sendMail(mailOptions, (error, info) => {
                    if (error) {
                        console.error('Error sending email:', error);
                        res.status(500).send('Error sending email.');
                    } else {
                        console.log('Email sent:', info.response);
                        res.status(200).send('Password reset email sent.');
                    }
                });
            } else {
                res.status(404).send('User not found.');
            }
        }
    });
});

app.get('/protected', verifyToken, (req, res) => {
    res.status(200).send({ message: 'This is a protected route.' });
});

app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});
