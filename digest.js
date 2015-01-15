'use strict';

angular.module('DigestAuthInterceptor', ['LocalStorageModule'])

.config(function ($locationProvider, $provide) {
  $provide.factory('digestAuthInterceptor', function ($q, $injector, $location, localStorageService, md5) {
    return {
      responseError: function (rejection) {
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

        if (rejection.status === 401) {
          var authHeader = rejection.headers('www-authenticate');
          if (rejection.headers('x-www-authenticate') != null) {
            authHeader = rejection.headers('x-www-authenticate');
          }

          if (!authHeader) {
            return $q.reject(rejection);
          }

          var
            $http = $injector.get('$http'),
            username = localStorageService.get('username'),
            password = localStorageService.get('password'),
            HA1 = localStorageService.get('authorization'),
            cnonce = genNonce(16),
            reg = /.+?\:\/\/.+?(\/.+?)(?:#|\?|$)/,
            nc = '00000001',
            nonce, realm, qop, opaque, algorithm;

          if ((username && password) || HA1) {
            var
              ws = '(?:(?:\\r\\n)?[ \\t])+',
              token = '(?:[\\x21\\x23-\\x27\\x2A\\x2B\\x2D\\x2E\\x30-\\x39\\x3F\\x41-\\x5A\\x5E-\\x7A\\x7C\\x7E]+)',
              quotedString = '"(?:[\\x00-\\x0B\\x0D-\\x21\\x23-\\x5B\\\\x5D-\\x7F]|' + ws + '|\\\\[\\x00-\\x7F])*"',
              tokenizer = new RegExp(token + '(?:=(?:' + quotedString + '|' + token + '))?', 'g'),
              tokens = authHeader.match(tokenizer),
              uri = reg.exec(rejection.config.url);

            if (uri == null) {
              uri = rejection.config.url;
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

            var HA2 = md5.createHash(rejection.config.method + ':' + uri);
            if (qop == 'auth-int') {
              entityBody = ""; //TODO: Implement
              HA2 = md5.createHash(rejection.config.method + ':' + uri + ':' + md5.createHash(entityBody));
            }

            var response = md5.createHash(HA1 + ':' + nonce + ':' + HA2);
            if (qop == 'auth' || qop == 'auth-int') {
              response = md5.createHash(HA1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + HA2);
            }

            var header = 'Digest username="' + username + '", realm="' + realm +
                        '", nonce="' + nonce + '", uri="' + uri +
                        '", algorithm=MD5, response="' + response +
                        '", opaque="' + opaque + '", qop="' + qop +
                        '", nc=' + nc + ', cnonce="' + cnonce + '"';

            $http.defaults.headers.common.authorization = header;

            var deferredResponse = $q.defer();

            var headers = rejection.config.headers;
            headers.Authorization = header;

            $http({
              method: rejection.config.method,
              url: rejection.config.url,
              crossDomain: true,
              contentType : 'application/json',
              headers: headers,
              transformRequest: rejection.config.transformRequest,
              transformResponse: rejection.config.transformResponse
            })
            .success(function (data, status, headers, config) {
              localStorageService.set('authorization', HA1);
              localStorageService.remove('password');

              deferredResponse.resolve({data: data, status: status, headers: headers, config: config});
            })
            .error(function () {
              deferredResponse.reject(rejection);
              localStorageService.clearAll();
            });

            return deferredResponse.promise;
          } else {
            $location.path('/login');
          }
        }
        return $q.reject(rejection);
      }
    };
  });
});
