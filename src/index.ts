import express, { Request, Response } from "express";
import { Pool, PoolClient } from "pg";
import dotenv from "dotenv";
import bcrypt from "bcrypt";

dotenv.config(); // Load environment variables

const app = express();
app.use(express.json());

// Ensure DB_URI is set
if (!process.env.DB_URI) {
    console.error("Error: DB_URI is not defined in environment variables.");
    process.exit(1);
}

// ✅ Use `pg.Pool` for efficient connection pooling
const pool = new Pool({
    connectionString: process.env.DB_URI,
});

pool.on("connect", () => {
    console.log("Connected to PostgreSQL ✅");
});

// ✅ SIGNUP Route (with better transaction handling)
app.post("/signup", async (req: Request, res: Response) => {
    let client: PoolClient | undefined;
    try {
        const { username, password, email } = req.body;

        // Validate Input
        if (!username || !password || !email) {
            return res.status(400).json({ error: "All fields are required" });
        }

        // ✅ Get a database connection from the pool
        client = await pool.connect();

        // ✅ Start a transaction
        await client.query("BEGIN");

        // Check if user already exists
        const existingUser = await client.query(
            "SELECT id FROM users WHERE username = $1 OR email = $2",
            [username, email]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: "Username or email already taken" });
        }

        // Hash the password
        const hashedPassword = await bcrypt.hash(password, 10);

        // Insert User
        const query = `
            INSERT INTO users (username, password, email) 
            VALUES ($1, $2, $3) 
            RETURNING id, username, email, created_at`;

        const values = [username, hashedPassword, email];

        const result = await client.query(query, values);

        // ✅ Commit transaction if everything succeeds
        await client.query("COMMIT");

        // ✅ Send response (excluding password)
        return res.status(201).json({
            id: result.rows[0].id,
            username: result.rows[0].username,
            email: result.rows[0].email,
            created_at: result.rows[0].created_at,
        });

    } catch (error: any) {
        // ❌ Rollback transaction on error
        if (client) await client.query("ROLLBACK");

        console.error("Error in /signup route:", error.stack);

        if (error.code === "23505") {
            return res.status(409).json({ error: "Username or email already exists" });
        }

        return res.status(500).json({ error: "Internal Server Error" });

    } finally {
        // ✅ Release the client back to the pool
        if (client) client.release();
    }
});

// ✅ Start the Express Server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT} 🚀`);
});
