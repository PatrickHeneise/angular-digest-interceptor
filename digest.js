'use strict';

angular.module('DigestAuthInterceptor', ['LocalStorageModule'])

.config(function ($locationProvider, $provide) {
  $provide.factory('digestAuthInterceptor', function ($q, $injector, $location, localStorageService, md5) {

    /* private values */
    var authHeader = null
      , username = localStorageService.get('username')
      , password = localStorageService.get('password')
      , HA1 = null
      ;

    var createHeader = function(method, url) {
      function genNonce(b) {
        var c = [],
          e = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789',
          a = e.length;
        for (var d = 0; d < b; ++d) {
          c.push(e[Math.random() * a | 0]);
        }
        return c.join('');
      }
      function unq(quotedString) {
        return quotedString.substr(1, quotedString.length - 2).replace(/(?:(?:\r\n)?[ \t])+/g, ' ');
      }

      if(!angular.isDefined(authHeader) || authHeader == null) {
        return null;
      }

      var nonce, 
          realm, 
          qop, 
          opaque, 
          algorithm,
          cnonce,
          nc;
      
      var reg = /.+?\:\/\/.+?(\/.+?)(?:#|\?|$)/,
          ws = '(?:(?:\\r\\n)?[ \\t])+',
          token = '(?:[\\x21\\x23-\\x27\\x2A\\x2B\\x2D\\x2E\\x30-\\x39\\x3F\\x41-\\x5A\\x5E-\\x7A\\x7C\\x7E]+)',
          quotedString = '"(?:[\\x00-\\x0B\\x0D-\\x21\\x23-\\x5B\\\\x5D-\\x7F]|' + ws + '|\\\\[\\x00-\\x7F])*"',
          tokenizer = new RegExp(token + '(?:=(?:' + quotedString + '|' + token + '))?', 'g');

      var tokens = authHeader.match(tokenizer),
          uri = reg.exec(url),
          cnonce = genNonce(16);
          nc = '00000001';

      if (uri == null) {
        uri = url;
      }

      tokens.forEach(function (value) {
        if (value.match('nonce')) {
          nonce = unq(value.split('=')[1]);
        }
        if (value.match('realm')) {
          realm = unq(value.split('=')[1]);
        }
        if (value.match('qop')) {
          qop   = unq(value.split('=')[1]);
        }
        if (value.match('algorithm')) {
          algorithm = unq(value.split('=')[1]);
        }
        if (value.match('opaque')) {
          opaque = unq(value.split('=')[1]);
        }
      });

      // http://en.wikipedia.org/wiki/Digest_access_authentication
      if (!HA1) {
        HA1 = md5.createHash(username + ':' + realm + ':' + password);

        if(algorithm == 'MD5-sess') {
          HA1 = md5.createHash(HA1 + ':' + nonce + ':' + cnonce);
        }
      }

      var HA2 = md5.createHash(method + ':' + uri);
      if (qop == 'auth-int') {
        entityBody = ""; //TODO: Implement
        HA2 = md5.createHash(method + ':' + uri + ':' + md5.createHash(entityBody));
      }

      var response = md5.createHash(HA1 + ':' + nonce + ':' + HA2);
      if (qop == 'auth' || qop == 'auth-int') {
        response = md5.createHash(HA1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + HA2);
      }

      return 'Digest username="' + username + '", realm="' + realm +
          '", nonce="' + nonce + '", uri="' + uri +
          '", algorithm=MD5, response="' + response +
          '", opaque="' + opaque + '", qop="' + qop +
          '", nc=' + nc + ', cnonce="' + cnonce + '"';
    }

    var digest = {
      failedQueue: {},

      request: function(config) {
        var header = createHeader(config.method, config.url);
        if (header) {
          config.headers.authorization = header;
        }

        return config;
      },

      responseError: function (rejection) {
        if (rejection.status === 400) {
          if (angular.isDefined(rejection.config.headers.authorization)) {
            rejection.status = 401;
            authHeader = null;
          }
        }

        if (rejection.status === 401 ) {
          if (angular.isDefined(rejection.config.headers.authorization)) {
            if(!angular.isDefined(digest.failedQueue[rejection.config.url])){
              digest.failedQueue[rejection.config.url] = -1;
            }

            digest.failedQueue[rejection.config.url] = digest.failedQueue[rejection.config.url] + 1;
          }

          if (digest.failedQueue[rejection.config.url] === 5) {
            delete digest.failedQueue[rejection.config.url];
            return $q.reject(rejection);
          }

          authHeader = rejection.headers('www-authenticate');
          if (rejection.headers('x-www-authenticate') != null) {
            authHeader = rejection.headers('x-www-authenticate');
          }

          if (!authHeader) {
            return $q.reject(rejection);
          }

          var
            $http = $injector.get('$http');

          if ((username && password) || HA1) {
            var header = createHeader(rejection.config.method, rejection.config.url);
            var deferredResponse = $q.defer();

            $http.defaults.headers.common.authorization = header;
            rejection.config.headers.authorization = header;

            $http({
              method: rejection.config.method,
              url: rejection.config.url,
              data: rejection.config.data,
              crossDomain: true,
              contentType : 'application/json',
              headers: rejection.config.headers,
              transformRequest: rejection.config.transformRequest,
              transformResponse: rejection.config.transformResponse
            })
            .success(function (data, status, headers, config) {
              password = null;

              deferredResponse.resolve({data: data, status: status, headers: headers, config: config});
            })
            .error(function () {
              HA1 = null;

              deferredResponse.reject(rejection);
            });

            return deferredResponse.promise;
          } else {
            $location.path('/login');
          }
        }

        return $q.reject(rejection);
      }
    };

    return digest;
  });
});
