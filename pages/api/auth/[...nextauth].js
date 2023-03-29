import NextAuth from "next-auth";
import CredentialProvider from "next-auth/providers/credentials";
import { connectToDatabase } from "../../../lib/bd";
import { verifyPassword } from "../../../lib/auth";

export default NextAuth({
  session: {
    strategy: "jwt",
  },
  providers: [
    CredentialProvider({
      async authorize(credentials) {
        const client = await connectToDatabase();

        const usersCollection = client.db().collection("users");

        // IF A USER IS FOUND
        const user = await usersCollection.findOne({
          email: credentials.email,
        });

        // IF A USER IS NOT FOUND
        if (!user) {
          client.close();
          throw new Error("No user found!");
        }

        // found a user with that email address, check for password
        const isValid = await verifyPassword(
          credentials.password,
          user.password
        );
        if (!isValid) {
          client.close();
          throw new Error("Could not log you in");
        }

        client.close();

        // authorization succeeded
        // return object that is encoded for JWT token
        return { email: user.email };
      },
    }),
  ],
});
