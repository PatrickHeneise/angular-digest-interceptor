'use strict';

angular.module('exampleApp')
  .controller('MainCtrl', function ($scope, $location, localStorageService) {
    var auth = localStorageService.get('auth');

    if (!auth) {
			$location.path('/login');
    }
  })

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