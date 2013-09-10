AngularJS Digest Authentication Interceptor
===========================================

Step-by-step
------------
1. Client request (no authentication)
2. Server responds with a 401 'Unauthorized' message, with realm and nonce in the WWW-Authenticate header
3. Interceptor received the 401 response and generates authrozation header, based on realm, nonce and username/password stored in the LocalStorage
4. Interceptor generates the original request with authorization headers and stores the hashed authrozation in the LocalStorage
5. Server responds with 200 'Success' if the credentials are correct. Otherwise the interceptor clears the LocalStorage and redirects to /login.


Todo
----
- Add original data/json to the second request


Example
-------
### client.js
Login controller:
		.controller('LoginFormCtrl', function ($scope, $http, localStorageService) {
			$scope.submit = function () {
				localStorageService.add('email', $scope.email);
				localStorageService.add('password', $scope.password);

				$http.post('http://127.0.0.1:3000/api/login', {
					headers: {'Content-Type': 'application/json'}
				}).then(function (response) {
					console.log('success', response);
				}, function (response) {
					console.log('error', response);
				});
			};
	  });


App config:
		$httpProvider.interceptors.push('digestAuthInterceptor');


### server.js
		passport.use(new DigestStrategy({
				qop: 'auth',
				realm: 'users@mydomain.com',
				usernameField: 'email',
			},
			function (username, done) {
				users.findOneAndUpdate(username, function (err, user) {
					if (err) { return done(err); }
					if (!user) {
						return done(null, false);
					} else {
						return done(null, user, user.password);
					}
				});
			},
			function (params, done) {
				process.nextTick(function () {
					return done(null, true);
				});
			}
		));

References
----------
http://www.sitepoint.com/understanding-http-digest-access-authentication/
http://en.wikipedia.org/wiki/Digest_access_authentication#Alternative_authentication_protocols
http://codingsmackdown.tv/blog/2013/01/02/using-response-interceptors-to-show-and-hide-a-loading-widget/
https://github.com/phpmasterdotcom/UnderstandingHTTPDigest/blob/master/client.php

Acknowledgements
----------------
Thanks to Jared Hanson (@jaredhanson) for PassportJS and the [passport-http authentication strategy](https://github.com/jaredhanson/passport-http) and to Greg Pipe (@grevory) for the [AngularJS LocalStorage Service](https://github.com/grevory/angular-local-storage).

License
-------
[The MIT License](http://opensource.org/licenses/MIT)

Copyright (c) 2013 Patrick Heneise (@patrickheneise) <[http://patrickheneise.com/](http://patrickheneise.com/)>