import NextAuth from 'next-auth';
import { authConfig } from './auth.config';
import Credentials from 'next-auth/providers/credentials';
import { z } from 'zod';
import { sql } from '@vercel/postgres';
import type { User } from '@/app/lib/definitions';
import bcrypt from 'bcrypt';
 
// 2. After validating the credentials, create a new getUser function that queries the user from the database.
async function getUser(email: string): Promise<User | undefined> {
  try {
    const user = await sql<User>`SELECT * FROM users WHERE email=${email}`;
    return user.rows[0];
  } catch (error) {
    console.error('Failed to fetch user:', error);
    throw new Error('Failed to fetch user.');
  }
}

export const { auth, signIn, signOut } = NextAuth({
  ...authConfig,
  providers: [
    // 1. Use zod to validate the email and password before checking if the user exists in the database
    Credentials({
        async authorize(credentials) {
          const parsedCredentials = z
            .object({ email: z.string().email(), password: z.string().min(6) })
            .safeParse(credentials);

            if (parsedCredentials.success) {
                const { email, password } = parsedCredentials.data;
                const user = await getUser(email);
                if (!user) return null;

                // 3. Then, call bcrypt.compare to check if the passwords match:
                const passwordsMatch = await bcrypt.compare(password, user.password);
                // 4. if the passwords match you want to return the user, otherwise, return null to prevent the user from logging in.
                if (passwordsMatch) return user;
            }
       
            return null;
        },
    }),
  ],
});