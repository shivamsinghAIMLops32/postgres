import express, { Request, Response } from "express";
import { Client } from "pg";
import dotenv from "dotenv";
import bcrypt from "bcrypt";

dotenv.config(); // Load environment variables before using them

const app = express();
app.use(express.json());

// Ensure DB_URI is defined
if (!process.env.DB_URI) {
    console.error("Error: DB_URI is not defined in environment variables.");
    process.exit(1); // Exit process if DB_URI is missing
}

const pgClient = new Client({ connectionString: process.env.DB_URI });

// Connect to the database with error handling
pgClient
    .connect()
    .then(() => console.log("Connected to PostgreSQL ✅"))
    .catch((err) => {
        console.error("Failed to connect to PostgreSQL ❌", err);
        process.exit(1); // Exit if database connection fails
    });

app.post("/signup", async (req: Request, res: Response) => {
    try {
        const { username, password, email } = req.body;

        // Validate Input
        if (!username || !password || !email) {
            return res.status(400).json({ error: "All fields are required" });
        }

        // Check if user already exists (to prevent duplicates)
        const existingUser = await pgClient.query(
            "SELECT id FROM users WHERE username = $1 OR email = $2",
            [username, email]
        );
        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: "Username or email already taken" });
        }

        // Hash the password before storing
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);


        // start the transaction
        await pgClient.query('BEGIN');
        // Insert User Query
        const query = `INSERT INTO users (username, password, email) 
                       VALUES ($1, $2, $3) RETURNING id, username, email, created_at`;

        const values = [username, hashedPassword, email];

        // Execute Query
        const result = await pgClient.query(query, values);

        // Send Response (excluding password for security)
        res.status(201).json({
            id: result.rows[0].id,
            username: result.rows[0].username,
            email: result.rows[0].email,
            created_at: result.rows[0].created_at,
        });

        // commit the transaction if evrything runs successfully
await pgClient.query('commit');
    } catch (error: any) {
        // if theres any error then get back to previous state of transaction
        await pgClient.query('ROLLBACK');
        console.error("Error in /signup route:", error.stack);

        if (error.code === "23505") {
            return res.status(409).json({ error: "Username or email already exists" });
        }

        res.status(500).json({ error: "Internal Server Error" });
    }finally{
        // end the transaction
        await pgClient.end();
    }
});

// Start Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} 🚀`);
});
