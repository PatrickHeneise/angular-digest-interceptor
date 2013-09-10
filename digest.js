'use strict';

angular.module('DigestAuthInterceptor', ['LocalStorageModule'])

.config(function ($locationProvider, $provide) {
  $provide.factory('digestAuthInterceptor', function ($q, $injector, $location, localStorageService) {
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
          var
            $http = $injector.get('$http'),
            email = localStorageService.get('email'),
            password = localStorageService.get('password'),
            HA1 = localStorageService.get('authorization'),
            cnonce = genNonce(10),
            reg = /.+?\:\/\/.+?(\/.+?)(?:#|\?|$)/,
            nc = 1,
            nonce, realm, qop;

          if ((email && password) || HA1) {
            var
              ws = '(?:(?:\\r\\n)?[ \\t])+',
              token = '(?:[\\x21\\x23-\\x27\\x2A\\x2B\\x2D\\x2E\\x30-\\x39\\x3F\\x41-\\x5A\\x5E-\\x7A\\x7C\\x7E]+)',
              quotedString = '"(?:[\\x00-\\x0B\\x0D-\\x21\\x23-\\x5B\\\\x5D-\\x7F]|' + ws + '|\\\\[\\x00-\\x7F])*"',
              tokenizer = new RegExp(token + '(?:=(?:' + quotedString + '|' + token + '))?', 'g'),
              tokens = rejection.headers('WWW-Authenticate').match(tokenizer),
              uri = reg.exec(rejection.config.url);

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
            });

            HA1 = HA1 ? HA1 : md5(email + ':' + realm + ':' + password);
            var
              HA2 = md5(rejection.config.method + ':' + uri[1]),
              response = md5(HA1 + ':' + nonce + ':' + nc + ':' + cnonce + ':' + qop + ':' + HA2),
              header = 'Digest username="' + email + '", realm="' + realm +
                        '", nonce="' + nonce + '", uri="' + uri[1] +
                        '", cnonce="' + cnonce + '", nc="' + nc +
                        '", qop="' + qop + '", response="' + response + '"';

            $http.defaults.headers.common.authorization = header;

            $http({
              method: rejection.config.method,
              url: rejection.config.url,
              crossDomain: true,
              contentType : 'application/json',
              headers: {
                'Authorization': header
              }
            })
            .success(function () {
              localStorageService.set('authorization', HA1);
              localStorageService.remove('password');

              var nextUrl = $location.search();
              if (nextUrl.next) {
                $location.search('');
                $location.path(nextUrl.next);
              } else {
                $location.path('/');
              }
            })
            .error(function () {
              localStorageService.clearAll();
              if ($location.path() !== '/login') {
                $location.search('next', $location.path());
              }
              $location.path('/login');
            });
          } else {
            $location.path('/login');
          }
        }
        return $q.reject(rejection);
      }
    };
  });
});
