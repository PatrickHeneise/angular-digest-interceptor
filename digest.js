'use strict';

angular
	.module('DigestAuthInterceptor', [
		'angular-md5',
		'LocalStorageModule'
	])
	.provider('digestAuthInterceptor', digestAuthInterceptorProvider);

function digestAuthInterceptorProvider() {
	var username = null,
		password = null,
		maximumRetries = 5,
		authenticationHeader = 'www-authenticate',
		credentialsInvalidPath = '/login';
	
	this.setUsername = function(value) { username = value; };
	this.setPassword = function(value) { password = value; };
	this.setMaximumRetries = function(value) { maximumRetries = value; };
	this.setCustomAuthenticationHeader = function(value) { authenticationHeader = value; };
	this.setCredentialsInvalidPath = function(value) { credentialsInvalidPath = value; };
	
	this.$get = digestAuthInterceptorFactory;
	
	digestAuthInterceptorFactory.$inject = ['$q', '$injector', '$location', 'md5', 'localStorageService'];
	function digestAuthInterceptorFactory($q, $injector, $location, md5, localStorageService) {
		return DigestAuthInterceptor(username, password, maximumRetries, authenticationHeader, credentialsInvalidPath, $q, $injector, $location, md5, localStorageService);
	}
}

function DigestAuthInterceptor(initialUsername, initialPassword, maximumRetries, authenticationHeader, credentialsInvalidPath, $q, $injector, $location, md5, localStorageService) {
	var authHeader = null,
		username = initialUsername,
		password = initialPassword,
		HA1 = null;
	
	var digest = {
		failedQueue: {},
		request: request,
		responseError: responseError
	};
	
	return digest;
	
	function request(config) {
		var header = createHeader(config.method, config.url);
		if (header) {
			config.headers.Authorization = header;
		}
		
		return config;
	}
	
	function responseError(rejection) {
		if ((rejection.status !== 400 && rejection.status !== 401) ||
			typeof rejection.config === 'undefined' ||
			typeof rejection.config.headers === 'undefined'
		) {
			return $q.reject(rejection);
		}
		
		if (typeof rejection.config.headers.authorization !== 'undefined') {
			rejection.config.headers.Authorization = rejection.config.headers.authorization;
			delete rejection.config.headers.authorization;
		}
		
		if (rejection.status === 400) {
			if (typeof rejection.config.headers.Authorization !== 'undefined') {
				rejection.status = 401;
				authHeader = null;
			}
		}
		
		if (rejection.status !== 401) {
			return $q.reject(rejection);
		}
		
		if (typeof rejection.config.headers.Authorization !== 'undefined') {
			if (typeof digest.failedQueue[rejection.config.url] === 'undefined') {
				digest.failedQueue[rejection.config.url] = -1;
			}
			
			digest.failedQueue[rejection.config.url] += 1;
		}
		
		if (digest.failedQueue[rejection.config.url] === maximumRetries) {
			delete digest.failedQueue[rejection.config.url];
			return $q.reject(rejection);
		}
		
		authHeader = rejection.headers(authenticationHeader);
		if (!authHeader) {
			return $q.reject(rejection);
		}
		
		if (!username || !password) {
			username = localStorageService.get('username');
			password = localStorageService.get('password');
		}
		
		if ((!username || !password) && !HA1) {
			$location.path(credentialsInvalidPath);
			return $q.reject(rejection);
		}
		
		var $http = $injector.get('$http'),
			header = createHeader(rejection.config.method, rejection.config.url),
			deferredResponse = $q.defer();
		
		$http.defaults.headers.common.Authorization = header;
		rejection.config.headers.Authorization = header;
		
		delete $http.defaults.headers.common.authorization;
		delete rejection.config.headers.authorization;
		
		$http({
			method:		rejection.config.method,
			url:    	rejection.config.url,
			params:		rejection.config.params,
			data:   	rejection.config.data,
			headers:	rejection.config.headers,
			crossDomain: true,
			contentType: rejection.config.contentType || 'application/json',
			transformRequest: rejection.config.transformRequest,
			transformResponse: rejection.config.transformResponse
		})
		.success(function(data, status, headers, config) {
			password = null;
			deferredResponse.resolve(
				{
					data: data,
					status: status,
					headers: headers,
					config: config
				}
			);
		})
		.error(function(httpReject) {
			HA1 = null;
			deferredResponse.reject(httpReject);
		});
		
		return deferredResponse.promise;
	}
	
	// private helper
	function createHeader(method, url) {
		if (authHeader === null) {
			return null;
		}
		
		var nonce,
			realm,
			qop,
			opaque,
			algorithm,
			reg = /.+?\:\/\/.+?(\/.+?)(?:#|\?|$)/,
			ws = '(?:(?:\\r\\n)?[ \\t])+',
			token = '(?:[\\x21\\x23-\\x27\\x2A\\x2B\\x2D\\x2E\\x30-\\x39\\x3F\\x41-\\x5A\\x5E-\\x7A\\x7C\\x7E]+)',
			quotedString = '"(?:[\\x00-\\x0B\\x0D-\\x21\\x23-\\x5B\\\\x5D-\\x7F]|' + ws + '|\\\\[\\x00-\\x7F])*"',
			tokenizer = new RegExp(token + '(?:=(?:' + quotedString + '|' + token + '))?', 'g'),
			tokens = authHeader.match(tokenizer),
			uri = reg.exec(url),
			cnonce = genNonce(16),
			nc = '00000001';
		
		if (uri === null) {
			uri = url;
		}
		
		for (var tokenKey in tokens) {
			if (!tokens.hasOwnProperty(tokenKey)) return;
			var value = tokens[tokenKey];
			
			if (value.match('nonce')) nonce = unq(value);
			if (value.match('realm')) realm = unq(value);
			if (value.match('qop')) qop = unq(value);
			if (value.match('algorithm')) algorithm = unq(value);
			if (value.match('opaque')) opaque = unq(value);
		}
		
		// http://en.wikipedia.org/wiki/Digest_access_authentication
		if (!HA1) {
			HA1 = md5.createHash([username, realm, password].join(':'));
			if (algorithm === 'MD5-sess') {
				HA1 = md5.createHash([HA1, nonce, cnonce].join(':'));
			}
		}
		
		var HA2 = md5.createHash([method, uri].join(':'));
		if (qop === 'auth-int') {
			entityBody = ''; // TODO: implement
			HA2 = md5.createHash([method, uri, md5.createHash(entityBody)].join(':'));
		}
		
		var response = md5.createHash([HA1, nonce, HA2].join(':'));
		if (qop === 'auth' || qop === 'auth-int') {
			response = md5.createHash([HA1, nonce, nc, cnonce, qop, HA2].join(':'));
		}
		
		var map = {
			username:	[username, true],
			realm:		[realm, true],
			nonce:		[nonce, true],
			uri:		[uri, true],
			algorithm:	['MD5', false],
			response:	[response, true],
			opaque:		[opaque, true],
			qop:		[qop, true],
			nc:			[nc, true],
			cnonce:		[cnonce, true]
		};
		
		return 'Digest ' + stringifyReturn(map);
		
		
		
		
		function genNonce(b) {
			var c = [],
				e = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
				a = e.length;
			
			for (var i = 0; i < b; ++i) {
				c.push(e[Math.random() * a |0]);
			}
			
			return c.join('');
		}
		
		function unq(value) {
			var quotedString = getRHSValue(value);
			return quotedString.substr(1, quotedString.length - 2).replace(/(?:(?:\r\n)?[ \t])+/g, ' ');
		}
		
		function stringifyReturn(map) {
			var intermediateArray = [];
			for (var key in map) {
				if (!map.hasOwnProperty(key)) return;
				var valueArray = map[key];
				
				var value = valueArray[0];
				if (valueArray[1] === true) {
					value = '"' + value + '"';
				}
				
				value = key + '=' + value;
				intermediateArray.push(value);
			}
			
			return intermediateArray.join(', ');
		}
	}

	function getRHSValue(someString) {
		someString.substr(someString.indexOf('='));
	}
}
