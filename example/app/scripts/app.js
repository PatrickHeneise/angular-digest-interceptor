'use strict';

angular.module('exampleApp', [
    'ngRoute',
    'LocalStorageModule',
    'DigestAuthInterceptor',
  ])
  .config(function ($routeProvider, $httpProvider) {
    $routeProvider
      .when('/', {
        templateUrl: 'views/main.html',
        controller: 'MainCtrl'
      })
      .when('/login', {
        templateUrl: 'views/login.html'
      })
      .otherwise({
        redirectTo: '/login'
      });

    $httpProvider.interceptors.push('digestAuthInterceptor');
  });
