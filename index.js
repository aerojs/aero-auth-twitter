let passport = require('passport')
let TwitterStrategy = require('passport-twitter').Strategy

module.exports = app => {
	app.on('startup loaded', () => {
		if(!app.auth || !app.auth.twitter)
			throw new Error('Missing Twitter configuration. Please define app.auth.twitter')

		if(!app.api.twitter || !app.api.twitter.id || !app.api.twitter.secret)
			throw new Error('Missing Twitter API keys. Please add them to security/api-keys.json')

		if(!app.auth.twitter.login)
			throw new Error("app.auth.twitter.login needs to be defined")

		if(app.auth.twitter.login.constructor.name === 'GeneratorFunction')
			app.auth.twitter.login = Promise.coroutine(app.auth.twitter.login)

		let config = {
			callbackURL: app.production ? `https://${app.config.domain}/auth/twitter/callback` : '/auth/twitter/callback',
			passReqToCallback: true,
			consumerKey: app.api.twitter.id,
			consumerSecret: app.api.twitter.secret
		}

		// Register Twitter strategy
		passport.use(new TwitterStrategy(config,
			function(request, accessToken, refreshToken, profile, done) {
				app.auth.twitter.login(profile._json)
				.then(user => done(undefined, user))
				.catch(error => done(error, false))
			}
		))

		// Twitter login
		app.get('/auth/twitter', passport.authenticate('twitter'))

		// Twitter callback
		app.get('/auth/twitter/callback',
			passport.authenticate('twitter', app.auth.twitter.onLogin || { successRedirect: '/' })
		)
	})
}