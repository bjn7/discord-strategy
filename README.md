# Discord OAuth2 Strategy for Passport.js

## Overview

This repository contains a custom OAuth2 strategy for authenticating with Discord using Passport.js. It facilitates user authentication via Discord and enables the retrieval of user data, including profile information, guilds, and connections.

## Installation

To use this strategy, first install Passport.js and then the custom strategy:

```bash
npm install passport discord-strategy
```

## Usage

Integrate the strategy into your Express application as follows:

### Example Setup

```javascript
const express = require("express");
const passport = require("passport");
const Strategy = require("discord-strategy");

const app = express();

// Define options for the Strategy
const options = {
  clientID: "YOUR_CLIENT_ID",
  clientSecret: "YOUR_CLIENT_SECRET",
  callbackURL: "http://localhost:3000/auth/discord/callback",
  scope: ["identify", "email", "guilds", "connections", "guilds.members.read"], // Example scopes
};

// Create a new instance of the Strategy
passport.use(new Strategy(options, verify));

async function verify(accessToken, refreshToken, profile, done, consume) {
  try {
    // Fetch connections, guilds, guild member concurrently
    await Promise.all([
      consume.connections(),
      consume.guilds(),
      console.memeber("613425648685547541"), //https://discord.com/developers/docs/resources/user#get-current-user
    ]);
    profile = consume.profile();
    console.log("Authentication successful!");
    done(null, profile);
  } catch (error) {
    done(error?.data || error, null);
  }
}

// Initialize Passport
app.use(passport.initialize());

// Define routes
app.get("/auth/discord", passport.authenticate("discord"));

app.get(
  "/auth/discord/callback",
  passport.authenticate("discord", { session: false }),
  (req, res) => {
    res.send(`
      <h1>Authentication successful!</h1>
      <h2>User Profile:</h2>
      <pre>${JSON.stringify(req.user, null, 2)}</pre>
    `);
  }
);

app.listen(3000, () => {
  console.log("Login via http://localhost:3000/auth/discord");
});
```

## Eample 2, Basic info Only

For scenarios where only basic user information is needed:

```javascript
function verify(accessToken, refreshToken, profile, done, consume) {
  console.log("Fetched", profile);
  return done(null, profile);
}
```

## Strategy Options

- **`clientID`**: Your Discord application's Client ID.
- **`clientSecret`**: Your Discord application's Client Secret.
- **`callbackURL`**: The URL to which Discord will redirect after authorization.
- **`scope`**: An array of scopes specifying the level of access (default: `["identify", "email"]`).

## Consumable Functions

With the v2.0 patch, all utility functions are now encapsulated in a new `consume` parameter.

List of Consumable Functions

- **`guilds(callback?)`**: Fetches the user's connections. Requires the `connections` scope.

```js
function verify(accessToken, refreshToken, profile, done, consume) {
  try {
    await consume.guilds(); //retuns void;
    profile = consume.profile(); //update profile, includes guild in `guilds` property.
    console.log(profile.guild);
    done(null, profile);
  } catch (err) {
    done(err, null);
  }
```

- **`connections(callback?)`**: Fetches the guilds the user is part of. Requires the `guilds` scope.

```js
await consume.connections(); //retuns void;
profile = consume.profile(); //update profile, includes guild in `connections` property.
console.log(profile.connections);
```

- **`guildJoiner(botToken: string, serverId: string, nickname: string, roles: string[], callback)`**: join the specified guild.

```js
await consume.guildJoiner(
  "botToken",
  "serverId",
  undefined,
  undefined,
  (err, result) =>
    !err && !result ? console.log("Joined") : console.log(err, result)
); //retuns void;
```

- **`member(guild_id: string)`**: Returns a guild member object for the current user and creates a member property inside the profile. Within the member property, there is a guild_id. If profile.member.guild_id is null, the user is not in that guild. This requires the guilds.members.read OAuth2 scope.

```js
await consume.member("id");
profile = consume.profile();
done(null, profile);
```

- **`resolver(key, api)`**: Fetches data from a specified API endpoint and stores it under the given key in the profile.

```js
await consume.resolver("guilds", "users/@me/guilds");
profile = consume.profile();
done(null, profile);
```

- **`consume.resolverCallbackBased(key, api, callback)`**: Allows customization of data fetching with more complex API interactions. The access token is sent as a query parameter btw.

- **`consume.profile()`**: Returns the updated user profile.

```js
done(null, consume.profile());
```

- **`consume.linkedRole.get()`**: Returns the application role connection for the user. Requires an `role_connections.write` scope.

- **`consume.linkedRole.set(platform_name?, platform_username?, metadata, done?)`**: Updates and returns the application role connection for the user. Requires an `role_connections.write` scope.

```js
// Role register Example
// fetch(
//   `https://discord.com/api/v10/applications/APPLICATION_ID_HERE/role-connections/metadata`,
//   {
//     method: "PUT",
//     body: JSON.stringify([
//       {
//         key: "cool",
//         name: "Cool ppl",
//         description: "You are cool ppl",
//         type: 7, //type 7: BOOLEAN_EQUAL
//       },
//     ]),
//     headers: {
//       "Content-Type": "application/json",
//       Authorization: `Bot BOT_TOKEN`,
//     },
//   }
// )
//   .then((r) => r.json())
//   .then(console.log);
//
// After registration do not forget to place url in designated field.
// Bot setting -> General Information -> Linked Roles Verification URL

await consume.set(undefined, undefined, {
  //key: value,
  cool: 1, //for type 7, value 1 represent true
});
done(null, profile);
```

### Example Usage

## Concurrent Data Fetching

```js
async function verify(accessToken, refreshToken, profile, done, consume) {
  try {
    await Promise.all([consume.connections(), consume.guilds()]);
    profile = consume.profile();
    console.log("[Asynchronous] Authentication successful!", profile);
    done(null, profile);
  } catch (err) {
    done(err, null);
  }
}
```

**Callback based Data Fetching (Not Recommended // extreme-slow)**

```js
async function verify(accessToken, refreshToken, profile, done, consume) {
  consume.connections((err) => {
    if (err) return done(err, false);
    consume.guilds((err) => {
      if (err) return done(err, false);
      console.log("[Synchronous] Authentication successful!", profile);
      done(null, profile);
    });
  });
}
```

### Resolver Functions

## Basic Get Resolver

```javascript
async function verify(accessToken, refreshToken, profile, done, consume) {
  try {
    await consume.resolver("guilds", "users/@me/guilds");
    profile = consume.profile();
    done(null, profile);
  } catch (err) {
    done(err, null);
  }
}
```

## Refresh Tokens and Additional Handling

If you need to store the `refreshToken`, manage sessions, or handle other processes unrelated to Discord OAuth, please refer to the Passport.js documentation for more information on managing these tasks or explore other strategies that might be necessary for additional handling.

## Changelog

### v2.2 Patch

- Added `consume.linkedRole.get` & `consume.linkedRole.get`. https://discord.com/developers/docs/resources/user#get-current-user-guild-member & https://discord.com/developers/docs/resources/user#get-current-user-application-role-connection

- Resolver function now rejects the promise instead of throwing an error.

### v2.1 Patch

- Added `consume.member("guild_id")`,Returns a guild member object for the current user. https://discord.com/developers/docs/resources/user#get-current-user-guild-member

- Resolver function now rejects the promise instead of throwing an error.

### v2.0.1 Patch

- Fixed typo and doc error

### v2.0 Patch

- Switched to an asynchronous approach `async/await` for non-blocking operations.
- Significantly improved performance compared to the previous version.
- Introduced the `consume` parameter to encapsulate utility functions.
- Removed the clean function, as the profile object is no longer need to be sanitize, replacement `consume.profile()` now returns a latest profile object.
- Added support for both asynchronous and callback-based resolvers.

### v1.1 Patch

- No longer required to pass the access token to the consumable functions.
- Added two new consumable functions: `complexResolver()` and `guildJoiner()`.

### v1.0.1 Patch

- Bound the cleaner function to the `clean` property of the profile (`profile.clean()`).
