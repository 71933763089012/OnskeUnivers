// app.js
import crypto from 'crypto';
import express from 'express';
import cookieParser from 'cookie-parser';
import fs, { mkdir } from 'fs/promises'; // use promises API for better async/await support
import path from 'path';
import { hashPassword, verifyPassword } from "./crypto-scrypt.js";

const app = express();
const PORT = 3000;
const ACCOUNTS_FILE = path.join(import.meta.dirname, '/data/accounts.json');

app.use(cookieParser())
app.use(express.json())

app.use('/', express.static(path.join(import.meta.dirname, 'public')));
app.listen(PORT, () => { console.log(`Server running on port: ${PORT}`) });

async function readAccounts() {
    try {
        const txt = await fs.readFile(ACCOUNTS_FILE, 'utf8');
        return JSON.parse(txt);
    } catch (err) {
        if (err.code === 'ENOENT') return []; // file not found -> start empty list
        throw err;
    }
}

async function writeAccounts(accounts) {
    // overwrite file with formatted JSON
    await fs.writeFile(ACCOUNTS_FILE, JSON.stringify(accounts, null, 2), 'utf8');
}

const illigalKeys = ['admin']
app.post('/onskeunivers/signup', async (req, res) => {
    try {
        let hasError = false;
        let errorMessages = { username: '', password: '', mail: '', birthday: '' };
        let body = { username: req.body.username || '', password: req.body.password || '', phone: req.body.mail || '', phone: req.body.birthday || '' }
        for (const [key, value] of Object.entries(body)) {
            if (illigalKeys.includes(key)) return res.status(403).send("Forbidden");
            const validation = await validateAccountSetting(key, value);
            if (validation !== true) {
                hasError = true;
                errorMessages[key] = validation;
            }
        }

        if (hasError) {
            res.status(400).json(errorMessages);
        } else {
            const { username = '', password = '', mail = '', birthday = '' } = body;
            const accounts = await readAccounts();
            const passwordHash = await hashPassword(password);
            accounts.push({
                username,
                password: passwordHash,
                owns: [],
                wishes: [],
                mail,
                birthday: 0,
            });
            await writeAccounts(accounts);

            updateUsername(res, username);
            res.status(200).send('Account created successfully');
        }
    } catch (err) {
        console.error('Error saving account:', err);
        res.status(500).send('Server error');
    }
});

app.post('/onskeunivers/login', async (req, res) => {
    try {
        const { username = '', password = '' } = req.body;

        let errorMessages = { username: '', password: '' };

        if (username === '') {
            errorMessages.username = 'This should be filled out';
        } else {
            const account = (await readAccounts()).find(account => account.username === username);
            if (account && await verifyPassword(password, account.password)) {
                updateUsername(res, username);
                res.status(200).send('Login successful');
                return;
            } else {
                errorMessages.username = 'Username or password is incorrect';
                errorMessages.password = 'Username or password is incorrect';
            }
        }

        if (password === '') {
            errorMessages.password = 'This should be filled out';

            if (username !== '') {
                errorMessages.username = 'Please enter your password';
            }
        }

        res.status(400).json(errorMessages);
    } catch (err) {
        console.error('Error logging in:', err);
        res.status(500).send('Server error');
    }
})

app.post("/onskeunivers/logout", (req, res) => {
    if (req.cookies) {
        Object.keys(req.cookies).forEach(name => {
            res.clearCookie(name, { path: "/" });
        });
    }
    res.redirect("/onskeunivers/login");
});


app.get('/onskeunivers/me', async (req, res) => {
    const username = req.cookies.username;
    if (!username) return res.status(401).send('Unauthorized');

    const accounts = await readAccounts();
    const account = accounts.find(acc => acc.username === username);
    if (!account) {
        return res.status(404).send('Account not found');
    }
    if (req.cookies.user_id !== hash(account.username)) {
        return res.status(403).send('Forbidden');
    }

    delete account['password'];
    res.json(account);
});

app.post('/onskeunivers/account', async (req, res) => {
    try {
        const username = req.cookies.username;
        if (!username) {
            return res.status(401).send("Unauthorized");
        }
        const accounts = await readAccounts();
        const accountIndex = accounts.findIndex(acc => acc.username === username);
        if (accountIndex === -1) return res.status(404).send("Account not found");

        const account = accounts[accountIndex];
        if (req.cookies.user_id !== hash(account.username)) return res.status(403).send("Forbidden");

        const { password, settings } = req.body;
        if (!password) return res.status(400).send("Password is required");

        if (!await verifyPassword(password, account.password)) return res.status(403).send("Incorrect password");

        if (settings) {
            for (const [key, value] of Object.entries(settings)) {
                if (key in account) {
                    if (illigalKeys.includes(key)) return res.status(403).send("Forbidden");
                    const validation = await validateAccountSetting(key, value);
                    if (validation !== true) return res.status(400).send(validation);
                    if (key == 'password') {
                        account.password = await hashPassword(value);
                    } else {
                        account[key] = value;
                        if (key == 'username') { updateUsername(res, value) }
                    }
                } else {
                    return res.status(400).send(`Invalid setting: ${key}`);
                }
            }
        }

        accounts[accountIndex] = account;
        await writeAccounts(accounts);
        res.status(200).send("Account updated successfully");
    } catch (err) {
        console.error("Error updating Account:", err);
        res.status(500).send("Internal server error");
    }
});

async function validateAccountSetting(key, value) {
    if (value === '') return 'This should be filled out';

    if (key == 'username') {
        if (!/^[A-Za-z0-9_]{3,16}$/.test(value)) return 'Invalid username';

        const accounts = await readAccounts();
        if (accounts.some(account => account.username === value)) return 'This account already exists';
    }

    if (key == 'password') {
        if (value.length < 8) return 'Must be at least 8 charectors';
        if (value === value.toLowerCase()) return 'Must contain at least 1 uppercase letter';
        if (value === value.toUpperCase()) return 'Must contain at least 1 lowercase letter';
        if (!/\d/.test(value)) return 'Must contain at least 1 number';
    }

    if (key == 'mail') {
        if (!value.includes("@")) return "Invalid mail adress";
    }

    if (key == 'birthday') {

    }

    return true;
}

function updateUsername(res, username) {
    res.cookie('user_id', hash(username), { secure: true, sameSite: 'Strict', httpOnly: true });
    res.cookie('username', username, { secure: true, sameSite: 'Strict', httpOnly: true });
}

let hashkey;
try {
    hashkey = await fs.readFile('./data/hashkey');
} catch (error) {
    await randomizeHash();
}

async function randomizeHash(size = 32) {
    const randomKey = crypto.randomBytes(size);
    await fs.writeFile('./data/hashkey', randomKey);
    hashkey = randomKey;
}

function hash(input) {
    return crypto.createHmac('sha256', hashkey).update(input).digest('hex');
}