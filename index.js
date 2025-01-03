const OAuth2Strategy = require("passport-oauth2");
const { InternalOAuthError } = require("passport-oauth2");
const url = require("node:url");
const utils = require("passport-oauth2/lib/utils");
const base64url = require("base64url");
const crypto = require("crypto");

const API_BASE = "https://discord.com/api/";

/**
 * Represents the Discord OAuth2 strategy for Passport.
 * Extends the base OAuth2Strategy to provide custom behavior for Discord's API.
 * @param {Object} options - Configuration options for the strategy.
 * @param {Function} verify - Verification callback for the strategy.
 * @throws Will throw an error if required options are missing.
 */
class Strategy extends OAuth2Strategy {
  constructor(options, verify) {
    options = options || {};
    options.authorizationURL = options.authorizationURL || "https://discord.com/api/oauth2/authorize";
    options.tokenURL = options.tokenURL || "https://discord.com/api/oauth2/token";
    options.scopeSeparator = options.scopeSeparator || " ";
    options.scope = options.scope || [
      "identify",
      "email",
    ];

    if (!options.callbackURL) throw new Error("Missing callbackURL property");
    if (!options.clientID) throw new Error("Missing clientID property");
    if (!options.clientSecret) throw new Error("Missing clientSecret property");
    super(options, verify);
    this.options = options;
    this.verify = verify;
    this.name = "discord";
    this._oauth2.useAuthorizationHeaderforGET(true);
  }

  /**
   * Fetches the user profile from Discord using the provided access token.
   * @param {string} accessToken - The access token for the user.
   * @param {Function} done - Callback to handle the user profile.
   */
  async userProfile(accessToken, done) {
    try {
      const profile = await this.resolveApi("users/@me", accessToken);
      const consumable = {
        guilds: this.getGuilds.bind(this, profile, accessToken),
        guildJoiner: this.guildJoiner.bind(this, profile, accessToken),
        connections: this.getConnection.bind(this, profile, accessToken),
        complexResolver: this._oauth2._request,
        profile: () => profile,
        resolver: async (key, api) => {
          try {
            const data = await this.resolveApi(api, accessToken);
            profile[key] = data;
            return profile;
          } catch (err) {
            throw err;
          }
        },
        resolverCallbackBased: async (key, api, done) => {
          try {
            const data = await this.resolveApi(api, accessToken);
            profile[key] = data;
            done(null, profile);
          } catch (err) {
            done(err, null);
          }
        },
      };
      profile.avatarUrl = profile.avatar
        ? `https://cdn.discordapp.com/avatars/${profile.id}/${profile.avatar}`
        : undefined;
      done(null, { profile, consumable });
    } catch (e) {
      done(e, null);
    }
  }

  /**
   * Retrieves the connections associated with the user's Discord account.
   * @param {Object} profile - The user's profile.
   * @param {string} accessToken - The access token for the user.
   * @throws Will throw an error if the required scope is not included.
   */
  async getConnection(profile, accessToken, done) {
    if (!this.options.scope || !this.options.scope.includes("connections")) {
      throw new Error("Missing Scope, 'connections'");
    }

    try {
      const connections = await this.resolveApi("users/@me/connections", accessToken);
      profile.connections = connections;
      if (done) done(null, profile)
    } catch (e) {
      if (done) return done(e, null)
      throw e;
    }
  }

  /**
   * Retrieves the guilds associated with the user's Discord account.
   * @param {Object} profile - The user's profile.
   * @param {string} accessToken - The access token for the user.
   * @throws Will throw an error if the required scope is not included.
   */
  async getGuilds(profile, accessToken, done) {
    if (!this.options.scope || !this.options.scope.includes("guilds")) {
      throw new Error("Missing Scope, 'guilds'");
    }

    try {
      const guilds = await this.resolveApi("users/@me/guilds", accessToken);
      profile.guilds = guilds;
      if (done) done(null, profile)
    } catch (e) {
      if (done) return done(e, null)
      throw e;
    }
  }

  /**
   * Adds a user to a guild with the specified roles and nickname.
   * @param {Object} profile - The user's profile.
   * @param {string} accessToken - The access token for the user.
   * @param {string} botToken - The bot token for guild authorization.
   * @param {string} serverId - The ID of the server to join.
   * @param {string} nick - The nickname to assign to the user.
   * @param {string[]} roles - The roles to assign to the user.
   * @param {Function} done - Callback for handling the result.
   */
  async guildJoiner(profile, accessToken, botToken, serverId, nick, roles, done) {
    if (!this.options.scope || !this.options.scope.includes("guilds.join")) {
      done(new Error("Missing Scope, 'guilds.join'"));
      return;
    }

    const body = {
      access_token: accessToken,
      nick,
      roles,
    };

    try {
      const res = await new Promise((resolve, reject) => {
        this._oauth2._request(
          "PUT",
          `${API_BASE}guilds/${serverId}/members/${profile.id}`,
          {
            Authorization: `Bot ${botToken}`,
            "content-type": "application/json",
          },
          JSON.stringify(body),
          null,
          (err, result, response) => {
            if (err) {
              reject(err);
            } else {
              resolve(response);
            }
          }
        );
      });
      if (res.statusCode === 201 || res.statusCode === 204) {
        done(null, null);
      } else {
        done(new Error(`Unexpected status code: ${res.statusCode}`));
      }
    } catch (error) {
      done(error);
    }
  }

  /**
   * Resolves an API endpoint and parses the response.
   * @param {string} api - The API endpoint to resolve.
   * @param {string} accessToken - The access token for the user.
   * @returns {Promise<Object>} The resolved data.
   * @throws Will throw an error for request or parsing issues.
   */
  async resolveApi(api, accessToken) {
    try {
      const result = await new Promise((resolve, reject) => {
        this._oauth2.get(`${API_BASE}${api}`, accessToken, (err, result) => {
          if (err) {
            reject(err);
          } else {
            resolve(result);
          }
        });
      });
      return JSON.parse(result);
    } catch (err) {
      if (err instanceof SyntaxError) {
        throw new Error("Failed to parse the user profile.");
      }
      throw new InternalOAuthError("Failed to resolve API", err);
    }
  }

  /**
   * Authenticate the request.
   * @param {Object} req - The request object.
   * @param {Object} options - Authentication options.
   */
  authenticate = function (req, options) {
    options = options || {};
    var self = this;

    if (req.query && req.query.error) {
      if (req.query.error == 'access_denied') {
        return this.fail({ message: req.query.error_description });
      } else {
        return this.error(new AuthorizationError(req.query.error_description, req.query.error, req.query.error_uri));
      }
    }

    var callbackURL = options.callbackURL || this._callbackURL;
    if (callbackURL) {
      var parsed = url.parse(callbackURL);
      if (!parsed.protocol) {
        // The callback URL is relative, resolve a fully qualified URL from the
        // URL of the originating request.
        callbackURL = url.resolve(utils.originalURL(req, { proxy: this._trustProxy }), callbackURL);
      }
    }

    var meta = {
      authorizationURL: this._oauth2._authorizeUrl,
      tokenURL: this._oauth2._accessTokenUrl,
      clientID: this._oauth2._clientId,
      callbackURL: callbackURL
    }

    if ((req.query && req.query.code) || (req.body && req.body.code)) {
      function loaded(err, ok, state) {
        if (err) { return self.error(err); }
        if (!ok) {
          return self.fail(state, 403);
        }

        var code = (req.query && req.query.code) || (req.body && req.body.code);

        var params = self.tokenParams(options);
        params.grant_type = 'authorization_code';
        if (callbackURL) { params.redirect_uri = callbackURL; }
        if (typeof ok == 'string') { // PKCE
          params.code_verifier = ok;
        }

        self._oauth2.getOAuthAccessToken(code, params,
          function (err, accessToken, refreshToken, params) {
            if (err) { return self.error(self._createOAuthError('Failed to obtain access token', err)); }
            if (!accessToken) { return self.error(new Error('Failed to obtain access token')); }

            self._loadUserProfile(accessToken, function (err, {
              profile,
              consumable,
            }) {
              if (err) { return self.error(err); }

              function verified(err, user, info) {
                if (err) { return self.error(err); }
                if (!user) { return self.fail(info); }

                info = info || {};
                if (state) { info.state = state; }
                self.success(user, info);
              }

              try {
                if (self._passReqToCallback) {
                  var arity = self._verify.length;
                  if (arity == 7) {
                    self._verify(req, accessToken, refreshToken, params, profile, verified, consumable);
                  } else { // arity == 6
                    self._verify(req, accessToken, refreshToken, profile, verified, consumable);
                  }
                } else {
                  var arity = self._verify.length;
                  if (arity == 6) {
                    self._verify(accessToken, refreshToken, params, profile, verified, consumable);
                  } else { // arity == 5
                    self._verify(accessToken, refreshToken, profile, verified, consumable);
                  }
                }
              } catch (ex) {
                return self.error(ex);
              }
            });
          }
        );
      }

      var state = (req.query && req.query.state) || (req.body && req.body.state);
      try {
        var arity = this._stateStore.verify.length;
        if (arity == 4) {
          this._stateStore.verify(req, state, meta, loaded);
        } else { // arity == 3
          this._stateStore.verify(req, state, loaded);
        }
      } catch (ex) {
        return this.error(ex);
      }
    } else {
      var params = this.authorizationParams(options);
      params.response_type = 'code';
      if (callbackURL) { params.redirect_uri = callbackURL; }
      var scope = options.scope || this._scope;
      if (scope) {
        if (Array.isArray(scope)) { scope = scope.join(this._scopeSeparator); }
        params.scope = scope;
      }
      var verifier, challenge;

      if (this._pkceMethod) {
        verifier = base64url(crypto.pseudoRandomBytes(32))
        switch (this._pkceMethod) {
          case 'plain':
            challenge = verifier;
            break;
          case 'S256':
            challenge = base64url(crypto.createHash('sha256').update(verifier).digest());
            break;
          default:
            return this.error(new Error('Unsupported code verifier transformation method: ' + this._pkceMethod));
        }
        params.code_challenge = challenge;
        params.code_challenge_method = this._pkceMethod;
      }

      var state = options.state;
      if (state && typeof state == 'string') {
        // NOTE: In passport-oauth2@1.5.0 and earlier, `state` could be passed as
        //       an object.  However, it would result in an empty string being
        //       serialized as the value of the query parameter by `url.format()`,
        //       effectively ignoring the option.  This implies that `state` was
        //       only functional when passed as a string value.
        //
        //       This fact is taken advantage of here to fall into the `else`
        //       branch below when `state` is passed as an object.  In that case
        //       the state will be automatically managed and persisted by the
        //       state store.
        params.state = state;

        var parsed = url.parse(this._oauth2._authorizeUrl, true);
        utils.merge(parsed.query, params);
        parsed.query['client_id'] = this._oauth2._clientId;
        delete parsed.search;
        var location = url.format(parsed);
        this.redirect(location);
      } else {
        function stored(err, state) {
          if (err) { return self.error(err); }

          if (state) { params.state = state; }
          var parsed = url.parse(self._oauth2._authorizeUrl, true);
          utils.merge(parsed.query, params);
          parsed.query['client_id'] = self._oauth2._clientId;
          delete parsed.search;
          var location = url.format(parsed);
          self.redirect(location);
        }

        try {
          var arity = this._stateStore.store.length;
          if (arity == 5) {
            this._stateStore.store(req, verifier, state, meta, stored);
          } else if (arity == 4) {
            this._stateStore.store(req, state, meta, stored);
          } else if (arity == 3) {
            this._stateStore.store(req, meta, stored);
          } else { // arity == 2
            this._stateStore.store(req, stored);
          }
        } catch (ex) {
          return this.error(ex);
        }
      }
    }
  };
}

module.exports = Strategy;
